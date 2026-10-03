"""
logtailer/tailer.py

Two threaded tail loops running in parallel:
  Thread 1 — FTP:  tails ProFTPd custom_user ExtendedLog
  Thread 2 — HTTP: tails nginx http_dl access log

FTP log format (7 pipe-delimited fields):
  [11/May/2026:18:04:13 +0000]|IP|USER|PATH|COMMAND|STATUS|BYTES
  Filter: STATUS==226, COMMAND==RETR (download) or STOR/APPE (upload)

HTTP log format (7 pipe-delimited fields, nginx http_dl format):
  2026-05-12T18:04:13+00:00|IP|USER|METHOD|URI|STATUS|BYTES
  Filter: METHOD==GET, STATUS==200 or 206

Both threads share the same DB connection pool and write to the same tables
with a 'source' column set to 'ftp' or 'http'.

username == 'anonftp' (FTP) or '-' (HTTP anon) → anon_downloads
any other real username                         → user_downloads
"""

import bz2
import gzip
import io
import os
import re
import tarfile
import time
import logging
import threading
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import psycopg2.pool

# ── Config ────────────────────────────────────────────────────────────────────
FTP_LOG_DIR          = os.environ.get("FTP_LOG_DIR",      "/logs/ftp")
HTTP_LOG_DIR         = os.environ.get("HTTP_LOG_DIR",     "/logs/http")
DB_URL               = os.environ.get("LOGS_DATABASE_URL", "")
FTP_POS_PATH         = os.environ.get("FTP_POS_PATH",     "/pos/ftp.pos")
HTTP_POS_PATH        = os.environ.get("HTTP_POS_PATH",    "/pos/http.pos")
POLL_INTERVAL        = float(os.environ.get("POLL_INTERVAL",        "1"))
REOPEN_INTERVAL      = float(os.environ.get("REOPEN_INTERVAL",      "60"))
CONFIG_POLL_INTERVAL = float(os.environ.get("CONFIG_POLL_INTERVAL", "10"))
BATCH_SIZE           = int(os.environ.get("BATCH_SIZE", "100"))
ANON_USER            = "anonftp"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [tailer] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("tailer")

# ── Nginx access log regex ────────────────────────────────────────────────────
# Matches: IP - USER [DD/Mon/YYYY:HH:MM:SS +ZONE] "METHOD URI PROTO" STATUS BYTES ...
_NGINX_RE = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+\-]\d{4})\]\s+'
    r'"(\S+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\d+)'
)

# ── FTP timestamp parser ──────────────────────────────────────────────────────
FTP_TS_RE = re.compile(
    r'^\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s[+\-]\d{4}\]$'
)
MONTHS = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12,
}


def parse_ftp_timestamp(ts_field: str) -> datetime:
    m = FTP_TS_RE.match(ts_field)
    if m:
        try:
            raw = m.group(1)
            day, rest    = raw.split("/", 1)
            mon_str, rest2 = rest.split("/", 1)
            year, time_part = rest2.split(":", 1)
            h, mi, s = time_part.split(":")
            return datetime(
                int(year), MONTHS[mon_str], int(day),
                int(h), int(mi), int(s), tzinfo=timezone.utc,
            )
        except Exception:
            pass
    return datetime.now(timezone.utc)


def parse_http_timestamp(ts_field: str) -> datetime:
    """Parse nginx $time_iso8601: 2026-05-12T18:04:13+00:00"""
    try:
        # normalize +00:00 → +0000 for fromisoformat compat
        ts = ts_field.replace("+00:00", "+0000").replace("-00:00", "+0000")
        # Python 3.11+ handles this natively; for 3.10 strip offset and treat as UTC
        if ts.endswith("+0000"):
            ts = ts[:-5]
        return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def parse_nginx_access_timestamp(ts_field: str) -> datetime:
    """Parse nginx combined log time: 12/May/2026:18:04:13 +0000"""
    try:
        return datetime.strptime(ts_field, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        return datetime.now(timezone.utc)


# ── DB connection pool ────────────────────────────────────────────────────────
_pool: psycopg2.pool.ThreadedConnectionPool | None = None
_pool_lock = threading.Lock()


def get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    with _pool_lock:
        if _pool is None:
            while True:
                try:
                    _pool = psycopg2.pool.ThreadedConnectionPool(
                        2, 6, DB_URL,
                        cursor_factory=psycopg2.extras.RealDictCursor,
                    )
                    log.info("Connected to logs database")
                    break
                except Exception as e:
                    log.warning("DB connection failed: %s — retrying in 5s", e)
                    time.sleep(5)
    return _pool


def get_conn():
    return get_pool().getconn()


def put_conn(conn):
    get_pool().putconn(conn)


# ── Schema bootstrap ──────────────────────────────────────────────────────────

def ensure_schema():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_downloads (
                    id         BIGSERIAL PRIMARY KEY,
                    logged_at  TIMESTAMPTZ NOT NULL,
                    ip_address INET NOT NULL,
                    username   TEXT NOT NULL,
                    filepath   TEXT NOT NULL,
                    filename   TEXT NOT NULL,
                    bytes      BIGINT,
                    source     TEXT NOT NULL DEFAULT 'ftp'
                )""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS anon_downloads (
                    id         BIGSERIAL PRIMARY KEY,
                    logged_at  TIMESTAMPTZ NOT NULL,
                    ip_address INET NOT NULL,
                    filepath   TEXT NOT NULL,
                    filename   TEXT NOT NULL,
                    bytes      BIGINT,
                    source     TEXT NOT NULL DEFAULT 'ftp'
                )""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_uploads (
                    id         BIGSERIAL PRIMARY KEY,
                    logged_at  TIMESTAMPTZ NOT NULL,
                    ip_address INET NOT NULL,
                    username   TEXT NOT NULL,
                    filepath   TEXT NOT NULL,
                    filename   TEXT NOT NULL,
                    bytes      BIGINT,
                    source     TEXT NOT NULL DEFAULT 'ftp'
                )""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS anon_uploads (
                    id         BIGSERIAL PRIMARY KEY,
                    logged_at  TIMESTAMPTZ NOT NULL,
                    ip_address INET NOT NULL,
                    filepath   TEXT NOT NULL,
                    filename   TEXT NOT NULL,
                    bytes      BIGINT,
                    source     TEXT NOT NULL DEFAULT 'ftp'
                )""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tailer_config (
                    key        TEXT PRIMARY KEY,
                    value      TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )""")
            # Add source column to existing tables if upgrading
            cur.execute("""
                ALTER TABLE user_downloads
                ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'ftp'
            """)
            cur.execute("""
                ALTER TABLE anon_downloads
                ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'ftp'
            """)
            for k, v in [
                ("log_filename",          "full_user.log"),
                ("log_retention_days",    "90"),
                ("log_retention_enabled", "true"),
                ("http_log_filename",     "http_downloads.log"),
                ("http_log_enabled",      "true"),
                ("tailer_status",         "starting"),
                ("tailer_last_write",     ""),
                ("tailer_pos",            "0"),
                ("http_tailer_pos",       "0"),
                ("tailer_total_rows",     "0"),
                ("upload_backfill_done",  "false"),
            ]:
                cur.execute(
                    "INSERT INTO tailer_config (key,value) VALUES (%s,%s) "
                    "ON CONFLICT (key) DO NOTHING",
                    (k, v),
                )
            cur.execute("""
                CREATE TABLE IF NOT EXISTS processed_archives (
                    id           SERIAL PRIMARY KEY,
                    filename     TEXT NOT NULL,
                    source       TEXT NOT NULL,
                    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    rows_inserted INT NOT NULL DEFAULT 0,
                    UNIQUE(filename, source)
                )
            """)
            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS idx_ud_logged_at   ON user_downloads(logged_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ud_username    ON user_downloads(username)",
                "CREATE INDEX IF NOT EXISTS idx_ud_source      ON user_downloads(source)",
                "CREATE INDEX IF NOT EXISTS idx_ud_source_time ON user_downloads(source, logged_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ud_source_user ON user_downloads(source, username, logged_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ad_logged_at   ON anon_downloads(logged_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ad_ip          ON anon_downloads(ip_address)",
                "CREATE INDEX IF NOT EXISTS idx_ad_source      ON anon_downloads(source)",
                "CREATE INDEX IF NOT EXISTS idx_ad_source_time ON anon_downloads(source, logged_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_uu_logged_at   ON user_uploads(logged_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_uu_username    ON user_uploads(username)",
                "CREATE INDEX IF NOT EXISTS idx_uu_ip          ON user_uploads(ip_address)",
                "CREATE INDEX IF NOT EXISTS idx_uu_filename    ON user_uploads(filename)",
                "CREATE INDEX IF NOT EXISTS idx_au_logged_at   ON anon_uploads(logged_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_au_ip          ON anon_uploads(ip_address)",
                "CREATE INDEX IF NOT EXISTS idx_au_filename    ON anon_uploads(filename)",
            ]:
                cur.execute(idx_sql)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS stats_cache (
                    cache_key   TEXT PRIMARY KEY,
                    data        JSONB NOT NULL,
                    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
        conn.commit()
        log.info("Schema ready")
    finally:
        put_conn(conn)


# ── Config helpers ────────────────────────────────────────────────────────────

def read_config(key: str, default: str = "") -> str:
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM tailer_config WHERE key = %s", (key,))
            row = cur.fetchone()
            return row["value"] if row else default
    finally:
        put_conn(conn)


def write_config(updates: dict):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            for k, v in updates.items():
                cur.execute(
                    "INSERT INTO tailer_config (key, value, updated_at) VALUES (%s,%s,NOW()) "
                    "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()",
                    (k, v),
                )
        conn.commit()
    finally:
        put_conn(conn)


# ── File position helpers ─────────────────────────────────────────────────────

def load_pos(path: str) -> int:
    try:
        with open(path) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_pos(path: str, pos: int):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(str(pos))


# ── Row insertion ─────────────────────────────────────────────────────────────

_TABLE_COLUMNS = {
    "user_downloads": ("logged_at", "ip_address", "username", "filepath", "filename", "bytes", "source"),
    "anon_downloads": ("logged_at", "ip_address", "filepath", "filename", "bytes", "source"),
    "user_uploads":   ("logged_at", "ip_address", "username", "filepath", "filename", "bytes", "source"),
    "anon_uploads":   ("logged_at", "ip_address", "filepath", "filename", "bytes", "source"),
}


def commit_rows(rows_by_table: dict):
    """rows_by_table: {table_name: [row_dict, ...]} for any of _TABLE_COLUMNS' tables."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            for table, rows in rows_by_table.items():
                if not rows:
                    continue
                cols = _TABLE_COLUMNS[table]
                psycopg2.extras.execute_values(
                    cur,
                    f"INSERT INTO {table} ({','.join(cols)}) VALUES %s ON CONFLICT DO NOTHING",
                    [tuple(r[c] for c in cols) for r in rows],
                )
        conn.commit()
    finally:
        put_conn(conn)


# ── FTP line parser ───────────────────────────────────────────────────────────

def parse_ftp_line(line: str) -> tuple | None:
    """
    Parse: [timestamp]|IP|USER|PATH|COMMAND|STATUS|BYTES
    Returns (table, row) or None.
    RETR (226) -> download row. STOR/APPE (226) -> upload row.
    """
    line = line.rstrip("\n\r")
    if not line:
        return None
    parts = line.split("|")
    if len(parts) != 7:
        return None
    ts_field, ip, user, filepath, command, status, raw_bytes = parts
    if status != "226":
        return None
    is_upload = command in ("STOR", "APPE")
    if command != "RETR" and not is_upload:
        return None
    if not filepath or filepath == "-":
        return None

    logged_at = parse_ftp_timestamp(ts_field)
    filename  = os.path.basename(filepath)
    bytes_val = int(raw_bytes) if raw_bytes.isdigit() else None
    ip        = ip   if ip   and ip   != "-" else "0.0.0.0"
    user      = user if user and user != "-" else ANON_USER

    row = {"logged_at": logged_at, "ip_address": ip,
           "filepath": filepath, "filename": filename,
           "bytes": bytes_val, "source": "ftp"}

    anon_table = "anon_uploads" if is_upload else "anon_downloads"
    user_table = "user_uploads" if is_upload else "user_downloads"

    if user == ANON_USER:
        return (anon_table, row)
    else:
        row["username"] = user
        return (user_table, row)


# ── HTTP line parser ──────────────────────────────────────────────────────────

def parse_http_line(line: str) -> tuple | None:
    """
    Parse nginx http_dl format:
      TIMESTAMP|IP|USER|METHOD|URI|STATUS|BYTES
      e.g. 2026-05-12T18:04:13+00:00|203.0.113.10|testuser|GET|/vendor/file.tar.gz|200|6139031

    Filter: METHOD==GET, STATUS==200 or 206
    USER=='-' → anonymous HTTP download
    """
    line = line.rstrip("\n\r")
    if not line:
        return None
    parts = line.split("|")
    if len(parts) != 7:
        return None
    ts_field, ip, user, method, uri, status, raw_bytes = parts

    if method != "GET":
        return None
    if status not in ("200", "206"):
        return None
    if not uri or uri == "-":
        return None

    # Strip query string from URI
    filepath = uri.split("?")[0]
    filename = os.path.basename(filepath)

    # Skip if it looks like a directory (no extension and ends with /)
    if filepath.endswith("/") or not filename:
        return None

    logged_at = parse_http_timestamp(ts_field)
    bytes_val = int(raw_bytes) if raw_bytes.isdigit() else None
    ip        = ip   if ip   and ip   != "-" else "0.0.0.0"
    is_anon   = not user or user == "-"

    row = {"logged_at": logged_at, "ip_address": ip,
           "filepath": filepath, "filename": filename,
           "bytes": bytes_val, "source": "http"}

    if is_anon:
        return ("anon_downloads", row)
    else:
        row["username"] = user
        return ("user_downloads", row)


def parse_nginx_access_line(line: str) -> tuple | None:
    """
    Parse standard nginx combined access log format:
      IP - USER [DD/Mon/YYYY:HH:MM:SS +ZONE] "METHOD URI PROTO" STATUS BYTES ...
    Used for historical archives that predate the custom pipe-delimited format.
    Only ingests GET 200/206 responses with a file-like URI path.
    """
    line = line.rstrip("\n\r")
    if not line:
        return None
    m = _NGINX_RE.match(line)
    if not m:
        return None
    ip, user, ts_field, method, uri, status, raw_bytes = m.groups()

    if method != "GET":
        return None
    if status not in ("200", "206"):
        return None

    filepath = uri.split("?")[0]
    filename = os.path.basename(filepath)
    if not filename or filepath.endswith("/"):
        return None

    logged_at = parse_nginx_access_timestamp(ts_field)
    bytes_val = int(raw_bytes) if raw_bytes.isdigit() else None
    ip        = ip if ip and ip != "-" else "0.0.0.0"
    is_anon   = not user or user == "-"

    row = {"logged_at": logged_at, "ip_address": ip,
           "filepath": filepath, "filename": filename,
           "bytes": bytes_val, "source": "http"}

    if is_anon:
        return ("anon_downloads", row)
    else:
        row["username"] = user
        return ("user_downloads", row)


def _detect_log_format(filepath: str) -> str:
    """Sniff the first non-empty line of an archive to determine format."""
    try:
        for line in _archive_lines(filepath):
            line = line.rstrip("\n\r")
            if not line:
                continue
            parts = line.split("|")
            if len(parts) == 7:
                return "pipe"
            if _NGINX_RE.match(line):
                return "nginx"
            return "unknown"
    except Exception:
        pass
    return "unknown"


def parse_http_auto(line: str) -> tuple | None:
    """Try pipe format first, fall back to nginx combined access log format."""
    result = parse_http_line(line)
    if result is not None:
        return result
    return parse_nginx_access_line(line)


# ── Archive ingestion ─────────────────────────────────────────────────────────

# Extensions treated as archive files (checked against lowercased filename)
_ARCHIVE_SUFFIXES = ('.tar.gz', '.tar.bz2', '.tar.xz', '.tgz', '.tbz2',
                     '.tar', '.gz', '.bz2', '.xz')


def _is_archive(fname: str) -> bool:
    fl = fname.lower()
    return any(fl.endswith(s) for s in _ARCHIVE_SUFFIXES)


def _archive_lines(filepath: str):
    """Generator yielding decoded text lines from any supported archive."""
    fl = filepath.lower()
    if fl.endswith(('.tar.gz', '.tar.bz2', '.tar.xz', '.tgz', '.tbz2', '.tar')):
        with tarfile.open(filepath, 'r:*') as tf:
            for member in sorted(tf.getmembers(), key=lambda m: m.name):
                if not member.isfile():
                    continue
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                mfl = member.name.lower()
                if mfl.endswith('.gz'):
                    fobj = gzip.open(fobj, 'rt', encoding='utf-8', errors='replace')
                elif mfl.endswith('.bz2'):
                    fobj = bz2.open(fobj, 'rt', encoding='utf-8', errors='replace')
                else:
                    fobj = io.TextIOWrapper(fobj, encoding='utf-8', errors='replace')
                yield from fobj
    elif fl.endswith('.gz'):
        with gzip.open(filepath, 'rt', encoding='utf-8', errors='replace') as f:
            yield from f
    elif fl.endswith(('.bz2', '.tbz2')):
        with bz2.open(filepath, 'rt', encoding='utf-8', errors='replace') as f:
            yield from f
    elif fl.endswith('.xz'):
        import lzma
        with lzma.open(filepath, 'rt', encoding='utf-8', errors='replace') as f:
            yield from f


def _is_archive_done(filename: str, source: str) -> bool:
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM processed_archives WHERE filename=%s AND source=%s",
                (filename, source),
            )
            return cur.fetchone() is not None
    finally:
        put_conn(conn)


def _mark_archive_done(filename: str, source: str, rows: int):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO processed_archives (filename, source, rows_inserted)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (filename, source) DO NOTHING""",
                (filename, source, rows),
            )
        conn.commit()
    finally:
        put_conn(conn)


def ingest_archives(log_dir: str, source: str, parser_fn, logger):
    """
    Scan log_dir for archive files and ingest any not yet recorded in
    processed_archives.  Files are processed in sorted (chronological) order.
    The current live log file is never an archive (no compressed extension),
    so it is naturally excluded.
    """
    try:
        entries = os.listdir(log_dir)
    except Exception as e:
        logger.warning("Cannot list log dir %s: %s", log_dir, e)
        return

    archives = sorted(f for f in entries if _is_archive(f))
    write_config({f"{source}_archive_total": str(len(archives))})
    if not archives:
        logger.info("[%s] No archive files found in %s", source, log_dir)
        return

    logger.info("[%s] Found %d archive(s) to check in %s", source, len(archives), log_dir)

    for fname in archives:
        if _is_archive_done(fname, source):
            logger.debug("[%s] Already ingested: %s", source, fname)
            continue

        filepath = os.path.join(log_dir, fname)
        logger.info("[%s] Ingesting archive: %s", source, fname)
        rows_by_table, total = {}, 0

        try:
            for line in _archive_lines(filepath):
                result = parser_fn(line)
                if result is None:
                    continue
                table, row = result
                rows_by_table.setdefault(table, []).append(row)

                if sum(len(v) for v in rows_by_table.values()) >= BATCH_SIZE * 10:
                    commit_rows(rows_by_table)
                    total += sum(len(v) for v in rows_by_table.values())
                    rows_by_table = {}

            if rows_by_table:
                commit_rows(rows_by_table)
                total += sum(len(v) for v in rows_by_table.values())

        except Exception as e:
            logger.error("[%s] Failed to ingest archive %s: %s", source, fname, e)
            continue

        _mark_archive_done(fname, source, total)
        logger.info("[%s] Archive %s: %d rows ingested", source, fname, total)


# ── One-time upload backfill ──────────────────────────────────────────────────

def backfill_uploads():
    """
    One-time scan of the *current* FTP log file for historical STOR/APPE lines
    that predate this feature (the live tailer already skipped past them while
    only recording downloads). Only inserts into user_uploads/anon_uploads —
    brand-new, empty tables — so re-reading lines whose downloads are already
    committed is safe; nothing is written to the download tables here.
    Guarded by tailer_config['upload_backfill_done'] so it only ever runs once.
    """
    if read_config("upload_backfill_done", "false").lower() in ("true", "1"):
        log.info("Upload backfill: already done, skipping")
        return

    filename = read_config("log_filename", "full_user.log")
    filepath = os.path.join(FTP_LOG_DIR, filename)
    log.info("Upload backfill: scanning %s for historical STOR/APPE entries…", filepath)

    rows_by_table, total = {}, 0
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                result = parse_ftp_line(line)
                if result is None:
                    continue
                table, row = result
                if table not in ("user_uploads", "anon_uploads"):
                    continue
                rows_by_table.setdefault(table, []).append(row)
                if sum(len(v) for v in rows_by_table.values()) >= BATCH_SIZE * 10:
                    commit_rows(rows_by_table)
                    total += sum(len(v) for v in rows_by_table.values())
                    rows_by_table = {}
        if rows_by_table:
            commit_rows(rows_by_table)
            total += sum(len(v) for v in rows_by_table.values())
        write_config({"upload_backfill_done": "true"})
        log.info("Upload backfill complete: %d rows inserted", total)
    except FileNotFoundError:
        log.warning("Upload backfill: log file not found (%s) — will retry next restart", filepath)
    except Exception as e:
        log.error("Upload backfill failed: %s — will retry next restart", e)


# ── Generic tail loop ─────────────────────────────────────────────────────────

def tail_loop(
    source: str,
    log_dir: str,
    pos_path: str,
    filename_key: str,
    enabled_key: str | None,
    pos_config_key: str,
    parser_fn,
    status_key: str | None = None,
):
    """
    Generic tail loop. source = 'ftp' or 'http'.
    Pass enabled_key=None to always tail (ignore any enable/disable config key).
    """
    logger = logging.getLogger(f"tailer.{source}")
    pos              = load_pos(pos_path)
    last_reopen      = time.monotonic()
    last_cfg_poll    = time.monotonic()
    fh               = None
    total_rows       = 0
    current_filename = read_config(filename_key, "full_user.log")
    current_log_path = os.path.join(log_dir, current_filename)
    enabled          = True if enabled_key is None else read_config(enabled_key, "true").lower() not in ("false", "0", "no")

    # If no local pos file, fall back to the DB-stored position so restarts
    # don't re-read the entire file from the beginning.
    if pos == 0:
        try:
            db_pos = int(read_config(pos_config_key, "0"))
            if db_pos > 0:
                pos = db_pos
                save_pos(pos_path, pos)
                logger.info("Restored pos from DB: %d", pos)
        except Exception:
            pass

    logger.info("Starting — file: %s, pos: %d", current_log_path, pos)

    while True:
        now = time.monotonic()

        # ── Poll config ───────────────────────────────────────────────────────
        if now - last_cfg_poll >= CONFIG_POLL_INTERVAL:
            last_cfg_poll = now
            try:
                if enabled_key is not None:
                    new_enabled = read_config(enabled_key, "true").lower() not in ("false","0","no")
                    if new_enabled != enabled:
                        enabled = new_enabled
                        logger.info("%s log tailer %s", source, "enabled" if enabled else "disabled")

                new_filename = read_config(filename_key, current_filename)
                if new_filename != current_filename:
                    logger.info("Filename changed: %s → %s", current_filename, new_filename)
                    current_filename = new_filename
                    current_log_path = os.path.join(log_dir, new_filename)
                    if fh:
                        fh.close()
                        fh = None
                    pos = 0
                    save_pos(pos_path, 0)
            except Exception as e:
                logger.warning("Config poll error: %s", e)

        if not enabled:
            time.sleep(POLL_INTERVAL * 5)
            continue

        # ── Open / reopen ─────────────────────────────────────────────────────
        if fh is None or (now - last_reopen) >= REOPEN_INTERVAL:
            if fh:
                try: fh.close()
                except Exception: pass
            try:
                fh = open(current_log_path, "r", encoding="utf-8", errors="replace")
                current_size = os.fstat(fh.fileno()).st_size
                if pos > current_size:
                    logger.info("File shrank (rotation) — seeking to 0")
                    pos = 0
                fh.seek(pos)
                last_reopen = now
            except FileNotFoundError:
                logger.warning("Log file not found: %s — retrying in 5s", current_log_path)
                fh = None
                time.sleep(5)
                continue

        # ── Read batch ────────────────────────────────────────────────────────
        rows_by_table = {}
        lines_read = 0

        while lines_read < BATCH_SIZE * 10:
            line = fh.readline()
            if not line:
                break
            lines_read += 1
            result = parser_fn(line)
            if result is None:
                continue
            table, row = result
            rows_by_table.setdefault(table, []).append(row)

        batch_total = sum(len(v) for v in rows_by_table.values())
        if batch_total == 0:
            new_pos = fh.tell()
            if new_pos != pos:
                pos = new_pos
                save_pos(pos_path, pos)
            time.sleep(POLL_INTERVAL)
            continue

        # ── Commit ────────────────────────────────────────────────────────────
        try:
            commit_rows(rows_by_table)
            pos = fh.tell()
            total_rows += batch_total
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            updates = {
                pos_config_key:    str(pos),
                "tailer_last_write": now_iso,
                "tailer_total_rows": str(total_rows),
            }
            if status_key:
                updates["tailer_status"] = "running"
            write_config(updates)
            save_pos(pos_path, pos)

            logger.info("Committed %s (total: %d, pos: %d)",
                        ", ".join(f"{len(v)} {t}" for t, v in rows_by_table.items()),
                        total_rows, pos)

        except Exception as e:
            logger.error("Commit error: %s", e)
            try: get_pool().putconn(None)
            except Exception: pass

        time.sleep(POLL_INTERVAL)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not DB_URL:
        raise RuntimeError("LOGS_DATABASE_URL environment variable is not set")

    # Wait for log directories
    for log_dir, label in [(FTP_LOG_DIR, "FTP"), (HTTP_LOG_DIR, "HTTP")]:
        if not os.path.isdir(log_dir):
            log.warning("%s log directory %s missing — waiting up to 60s", label, log_dir)
            for _ in range(30):
                if os.path.isdir(log_dir):
                    break
                time.sleep(2)

    ensure_schema()
    write_config({"tailer_status": "running", "ingestion_phase": "archives"})

    # Ingest any archived log files before starting the live tail loops
    log.info("Scanning for archived FTP logs…")
    ingest_archives(FTP_LOG_DIR, "ftp", parse_ftp_line, log)
    log.info("Scanning for archived HTTP logs…")
    # parse_http_auto tries pipe format first, then falls back to nginx combined format
    ingest_archives(HTTP_LOG_DIR, "http", parse_http_auto, log)
    backfill_uploads()
    write_config({"ingestion_phase": "tailing"})

    # Start HTTP tailer in a daemon thread
    http_thread = threading.Thread(
        target=tail_loop,
        kwargs=dict(
            source="http",
            log_dir=HTTP_LOG_DIR,
            pos_path=HTTP_POS_PATH,
            filename_key="http_log_filename",
            enabled_key="http_log_enabled",
            pos_config_key="http_tailer_pos",
            parser_fn=parse_http_line,
        ),
        daemon=True,
        name="http-tailer",
    )
    http_thread.start()
    log.info("HTTP tailer thread started")

    # FTP tail runs in the main thread; always enabled independent of retention setting
    tail_loop(
        source="ftp",
        log_dir=FTP_LOG_DIR,
        pos_path=FTP_POS_PATH,
        filename_key="log_filename",
        enabled_key=None,
        pos_config_key="tailer_pos",
        parser_fn=parse_ftp_line,
        status_key="tailer_status",
    )
