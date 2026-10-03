"""
backend/logs.py

Read-only PostgreSQL access for FTP/HTTP download activity logs.
Connects to the separate db_logs container.
Also reads/writes tailer_config for settings and status.
"""

import csv
import io
import json
import threading
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

import psycopg2
import psycopg2.extras
import psycopg2.pool

from config import settings

from config import settings

# ── Connection pool ───────────────────────────────────────────────────────────
# Threaded (not Simple) pool: FastAPI runs sync route handlers in a worker
# threadpool, and background stats-cache refreshes (see _swr below) add
# another concurrent thread on top of that, so getconn()/putconn() need the
# pool's own locking rather than assuming single-threaded access.
_pool: psycopg2.pool.ThreadedConnectionPool | None = None


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            1, 10,
            settings.logs_database_url,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
    return _pool


class _Ctx:
    def __enter__(self):
        self.c = _get_pool().getconn()
        return self.c
    def __exit__(self, *_):
        _get_pool().putconn(self.c)


def _conn():
    return _Ctx()


def _q(conn, sql: str, params=()) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def _q1(conn, sql: str, params=()) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


# ── Stats cache ───────────────────────────────────────────────────────────────

_cache_table_ready = False
_CACHE_TTL = "5 minutes"


def _ensure_cache_table():
    global _cache_table_ready
    if _cache_table_ready:
        return
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS stats_cache (
                    cache_key   TEXT PRIMARY KEY,
                    data        JSONB NOT NULL,
                    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ud_source_time
                    ON user_downloads(source, logged_at DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ud_source_user
                    ON user_downloads(source, username, logged_at DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ad_source_time
                    ON anon_downloads(source, logged_at DESC)
            """)
        conn.commit()
    _cache_table_ready = True


def _cache_get_any(key: str):
    """Look up a cache row regardless of age.

    Returns (data, is_fresh): data is None if nothing has ever been computed
    for this key; is_fresh is True while inside the TTL window.
    """
    try:
        _ensure_cache_table()
        with _conn() as conn:
            row = _q1(conn,
                f"SELECT data, (computed_at > NOW() - INTERVAL '{_CACHE_TTL}') AS is_fresh "
                f"FROM stats_cache WHERE cache_key = %s",
                (key,))
            if row and row["data"] is not None:
                return row["data"], bool(row["is_fresh"])  # JSONB already deserialized
    except Exception:
        pass
    return None, False


def _json_safe(value):
    """Recursively convert Decimal to int/float so cached values round-trip
    as JSON numbers, not strings.

    Postgres SUM(bigint) returns numeric, which psycopg2 maps to
    decimal.Decimal — plain json.dumps can't serialize that, so without this
    it silently falls back to stringifying it (e.g. "130444277761" instead
    of 130444277761). The frontend then does `a.current + b.current` on two
    of those, and JS's `+` concatenates strings instead of adding numbers,
    producing a garbage total.
    """
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def _cache_set(key: str, data):
    try:
        _ensure_cache_table()
        with _conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO stats_cache (cache_key, data, computed_at) "
                    "VALUES (%s, %s::jsonb, NOW()) "
                    "ON CONFLICT (cache_key) DO UPDATE "
                    "SET data = EXCLUDED.data, computed_at = NOW()",
                    (key, json.dumps(_json_safe(data))),
                )
            conn.commit()
    except Exception:
        pass


# ── Stale-while-revalidate ────────────────────────────────────────────────────
# These aggregate queries scan millions of rows and can take 10-30s+ once the
# combined (all-sources) case has to fall back to a live query. Blocking a
# request on that is what made pages feel broken rather than slow, so instead:
# always hand back the last computed value immediately (even past the 5-minute
# TTL) and kick off a background refresh; only a key that has *never* been
# computed pays the synchronous cost.

_bg_inflight: set[str] = set()
_bg_inflight_lock = threading.Lock()


def _refresh_in_background(key: str, compute):
    with _bg_inflight_lock:
        if key in _bg_inflight:
            return  # a refresh for this key is already running
        _bg_inflight.add(key)

    def _run():
        try:
            _cache_set(key, compute())
        except Exception:
            pass
        finally:
            with _bg_inflight_lock:
                _bg_inflight.discard(key)

    threading.Thread(target=_run, daemon=True, name=f"stats-refresh:{key}").start()


def _swr(key: str, compute):
    data, fresh = _cache_get_any(key)
    if data is not None:
        if not fresh:
            _refresh_in_background(key, compute)
        return data
    result = compute()
    _cache_set(key, result)
    return result


def warmup_stats_cache():
    """Pre-compute common stats combinations so page loads are instant."""
    # Cheap (indexed MIN lookups) — warms the "Max" button's label/target for
    # every source scope without touching the expensive aggregate queries.
    for source in (None, "ftp", "http"):
        try:
            get_earliest_activity(source=source)
        except Exception:
            pass
    # 730 (2y) is included since it's a bounded, fixed addition; the
    # dynamically-discovered "Max" value deliberately is not — for a
    # combined, multi-year-archive source that could be several times more
    # data than 2y covers, and warming it here would block startup for
    # everyone. It still works fine on first click: that request pays a live
    # compute once via _swr's cold path, then stays cached and self-refreshes
    # like any other key.
    for days in (1, 7, 30, 90, 365, 730):
        for source in (None, "ftp", "http"):
            bucket = "hour" if days <= 1 else "day"
            try:
                get_summary(days=days, source=source)
                get_user_download_timeline(days=days, bucket=bucket, source=source)
                get_anon_download_timeline(days=days, bucket=bucket, source=source)
                get_user_download_breakdown(days=days, source=source)
            except Exception:
                pass
    try:
        get_user_download_stats()  # combined ftp+http, powers the Overview page
    except Exception:
        pass
    for source in ("ftp", "http"):
        try:
            get_user_download_stats(source=source)
            get_user_download_stats(source=source, exclude_username=settings.public_http_username)
            get_user_download_stats(source=source, username_exact=settings.public_http_username)
            get_anon_download_stats(source=source)
        except Exception:
            pass
    try:
        get_user_upload_stats()
        get_anon_upload_stats()
        get_upload_timeline(days=30, bucket="day")
    except Exception:
        pass


# ── Tailer config helpers ─────────────────────────────────────────────────────

def get_tailer_config(key: str) -> Optional[str]:
    with _conn() as conn:
        row = _q1(conn, "SELECT value FROM tailer_config WHERE key = %s", (key,))
        return row["value"] if row else None


def set_tailer_config(key: str, value: str):
    with _conn() as conn:
        conn.cursor().execute(
            """
            INSERT INTO tailer_config (key, value, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """,
            (key, value),
        )
        conn.commit()


def get_log_filename() -> str:
    return get_tailer_config("log_filename") or "full_user.log"


def get_retention_days() -> int:
    v = get_tailer_config("log_retention_days")
    try:
        return int(v) if v else 90
    except ValueError:
        return 90


def get_retention_enabled() -> bool:
    v = get_tailer_config("log_retention_enabled")
    return v.lower() not in ("false", "0", "no") if v else True


def update_log_settings(log_filename: Optional[str], retention_days: Optional[int],
                        retention_enabled: Optional[bool] = None,
                        http_log_filename: Optional[str] = None,
                        http_log_enabled: Optional[bool] = None):
    if log_filename is not None:
        set_tailer_config("log_filename", log_filename)
    if retention_days is not None:
        set_tailer_config("log_retention_days", str(retention_days))
    if retention_enabled is not None:
        set_tailer_config("log_retention_enabled", "true" if retention_enabled else "false")
    if http_log_filename is not None:
        set_tailer_config("http_log_filename", http_log_filename)
    if http_log_enabled is not None:
        set_tailer_config("http_log_enabled", "true" if http_log_enabled else "false")


def get_system_status() -> dict:
    with _conn() as conn:
        rows = _q(conn, "SELECT key, value FROM tailer_config")
        cfg = {r["key"]: r["value"] for r in rows}

        ud_total = _q1(conn, "SELECT COUNT(*) AS n FROM user_downloads")["n"]
        ad_total = _q1(conn, "SELECT COUNT(*) AS n FROM anon_downloads")["n"]

    return {
        "log_filename":            cfg.get("log_filename", "full_user.log"),
        "log_retention_days":      int(cfg.get("log_retention_days", "90")),
        "log_retention_enabled":   cfg.get("log_retention_enabled", "true").lower() not in ("false", "0", "no"),
        "http_log_filename":       cfg.get("http_log_filename", "http_downloads.log"),
        "http_log_enabled":        cfg.get("http_log_enabled", "true").lower() not in ("false", "0", "no"),
        "tailer_status":           cfg.get("tailer_status", "unknown"),
        "tailer_last_write":       cfg.get("tailer_last_write", ""),
        "tailer_pos":              int(cfg.get("tailer_pos", "0")),
        "tailer_total_rows":       ud_total + ad_total,
    }


# ── Database info & archive ingestion stats ───────────────────────────────────

def get_db_stats() -> dict:
    """Return database sizes, table stats, archive ingestion progress, and tailer status."""
    with _conn() as conn:
        # Approximate row counts and sizes from pg catalogs (fast, no full scan)
        table_rows = _q(conn, """
            SELECT c.relname AS name,
                   GREATEST(s.n_live_tup, 0) AS rows,
                   pg_total_relation_size(c.oid) AS bytes
            FROM pg_class c
            LEFT JOIN pg_stat_user_tables s ON s.relname = c.relname
            WHERE c.relname IN (
                'user_downloads','anon_downloads',
                'user_uploads','anon_uploads',
                'processed_archives','stats_cache','tailer_config'
            ) AND c.relkind = 'r'
            ORDER BY bytes DESC NULLS LAST
        """)

        db_bytes = _q1(conn, "SELECT pg_database_size(current_database()) AS sz")["sz"]

        # Archive ingestion: per-source totals
        arch_totals = _q(conn, """
            SELECT source,
                   COUNT(*)                                   AS processed,
                   COUNT(*) FILTER (WHERE rows_inserted > 0) AS with_data,
                   COUNT(*) FILTER (WHERE rows_inserted = 0) AS empty_files,
                   COALESCE(SUM(rows_inserted), 0)           AS rows_ingested,
                   MAX(processed_at)                         AS last_processed
            FROM processed_archives
            GROUP BY source
        """)

        # Recent processing rate: files completed in the last 10 minutes
        arch_rate = _q(conn, """
            SELECT source,
                   COUNT(*) AS files_10m
            FROM processed_archives
            WHERE processed_at >= NOW() - INTERVAL '10 minutes'
            GROUP BY source
        """)

        # Tailer config (all keys)
        cfg_rows = _q(conn, "SELECT key, value FROM tailer_config")
        cfg = {r["key"]: r["value"] for r in cfg_rows}

    # Build per-source archive info
    arch_map = {r["source"]: r for r in arch_totals}
    rate_map = {r["source"]: int(r["files_10m"] or 0) for r in arch_rate}
    archives = {}
    for src in ("ftp", "http"):
        total     = int(cfg.get(f"{src}_archive_total", "0"))
        p         = arch_map.get(src, {})
        processed = int(p.get("processed") or 0)
        last_ts   = p.get("last_processed")
        files_10m = rate_map.get(src, 0)
        rate_per_min = files_10m / 10.0 if files_10m > 0 else 0.0
        remaining = max(0, total - processed)
        eta_secs  = int(remaining / rate_per_min * 60) if rate_per_min > 0 and remaining > 0 else 0
        archives[src] = {
            "total":        total,
            "processed":    processed,
            "with_data":    int(p.get("with_data") or 0),
            "empty_files":  int(p.get("empty_files") or 0),
            "rows_ingested": int(p.get("rows_ingested") or 0),
            "last_processed": last_ts.isoformat() if hasattr(last_ts, "isoformat") else (last_ts or ""),
            "rate_per_min": round(rate_per_min, 2),
            "eta_seconds":  eta_secs,
            "done": (total > 0 and processed >= total) or cfg.get("ingestion_phase") == "tailing",
        }

    def _row(r):
        return {"name": r["name"], "rows": int(r["rows"] or 0), "bytes": int(r["bytes"] or 0)}

    return {
        "db_bytes":        int(db_bytes or 0),
        "tables":          [_row(r) for r in table_rows],
        "archives":        archives,
        "ingestion_phase": cfg.get("ingestion_phase", "unknown"),
        "tailer": {
            "status":          cfg.get("tailer_status", "unknown"),
            "ftp_pos":         int(cfg.get("tailer_pos", "0")),
            "ftp_last_write":  cfg.get("tailer_last_write", ""),
            "http_pos":        int(cfg.get("http_tailer_pos", "0")),
            "http_last_write": cfg.get("http_tailer_last_write", cfg.get("tailer_last_write", "")),
        },
    }


# ── Retention pruning ─────────────────────────────────────────────────────────

def prune_old_records():
    """Delete rows older than the configured retention period. Skipped if disabled."""
    if not get_retention_enabled():
        return 0, 0
    days = get_retention_days()
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM user_downloads WHERE logged_at < NOW() - INTERVAL '%s days'",
                (days,),
            )
            ud = cur.rowcount
            cur.execute(
                "DELETE FROM anon_downloads WHERE logged_at < NOW() - INTERVAL '%s days'",
                (days,),
            )
            ad = cur.rowcount
        conn.commit()
    return ud, ad


# ── Filter builder ────────────────────────────────────────────────────────────

def _where(
    username: Optional[str] = None,
    ip: Optional[str] = None,
    filename: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    source: Optional[str] = None,
    exclude_username: Optional[str] = None,
    username_exact: Optional[str] = None,
) -> tuple[str, list]:
    clauses, params = [], []
    if username:
        clauses.append("username ILIKE %s")
        params.append(f"%{username}%")
    if username_exact:
        clauses.append("username = %s")
        params.append(username_exact)
    if exclude_username:
        clauses.append("username != %s")
        params.append(exclude_username)
    if ip:
        clauses.append("HOST(ip_address) ILIKE %s")
        params.append(f"%{ip}%")
    if filename:
        clauses.append("(filename ILIKE %s OR filepath ILIKE %s)")
        params.extend([f"%{filename}%", f"%{filename}%"])
    if date_from:
        clauses.append("logged_at >= %s")
        params.append(date_from)
    if date_to:
        clauses.append("logged_at <= %s")
        params.append(date_to)
    if source and source in ("ftp", "http"):
        clauses.append("source = %s")
        params.append(source)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


# HTTP anonymous traffic is logged under the shared public credential
# (settings.public_http_username, PUBLIC_HTTP_USERNAME) into user_downloads rather than anon_downloads (see logtailer/tailer.py —
# only FTP's 'anonftp' and HTTP's literal '-' route to anon_downloads). These
# two helpers let "registered" and "anon" aggregates classify it correctly
# regardless of which source filter is requested.

# Validated against [A-Za-z0-9_.-] in config.py, so safe to embed in SQL.
_PUB = settings.public_http_username


def _registered_downloads_sql(source: Optional[str] = None) -> str:
    if source == "ftp":
        return "user_downloads WHERE source = 'ftp'"
    if source == "http":
        return f"user_downloads WHERE source = 'http' AND username != '{_PUB}'"
    return f"user_downloads WHERE NOT (source = 'http' AND username = '{_PUB}')"


def _anon_downloads_sql(source: Optional[str] = None) -> str:
    if source == "ftp":
        return "(SELECT logged_at, bytes FROM anon_downloads WHERE source = 'ftp') anon_eff"
    if source == "http":
        return f"(SELECT logged_at, bytes FROM user_downloads WHERE source = 'http' AND username = '{_PUB}') anon_eff"
    return f"""(
        SELECT logged_at, bytes FROM anon_downloads
        UNION ALL
        SELECT logged_at, bytes FROM user_downloads WHERE source = 'http' AND username = '{_PUB}'
    ) anon_eff"""


def _ser(row) -> dict:
    out = {}
    for k, v in dict(row).items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


# ── User downloads ────────────────────────────────────────────────────────────

def get_user_downloads(
    page: int = 1, limit: int = 100,
    username: Optional[str] = None, ip: Optional[str] = None,
    filename: Optional[str] = None, date_from: Optional[str] = None,
    date_to: Optional[str] = None, source: Optional[str] = None,
    exclude_username: Optional[str] = None,
    username_exact: Optional[str] = None,
) -> dict:
    limit  = min(limit, 500)
    offset = (page - 1) * limit
    where, params = _where(username=username, ip=ip, filename=filename,
                           date_from=date_from, date_to=date_to, source=source,
                           exclude_username=exclude_username, username_exact=username_exact)
    with _conn() as conn:
        total = _q1(conn, f"SELECT COUNT(*) AS n FROM user_downloads{where}", params)["n"]
        rows  = _q(conn,
            f"""SELECT id, logged_at AT TIME ZONE 'UTC' AS logged_at,
                       HOST(ip_address) AS ip_address,
                       username, filepath, filename, bytes, source
                FROM user_downloads{where}
                ORDER BY logged_at DESC LIMIT %s OFFSET %s""",
            params + [limit, offset],
        )
    return {
        "total": total, "page": page, "limit": limit,
        "pages": max(1, -(-total // limit)),
        "rows": [_ser(r) for r in rows],
    }


def get_user_downloads_for_user(username: str, limit: int = 50) -> list:
    with _conn() as conn:
        rows = _q(conn,
            """SELECT id, logged_at AT TIME ZONE 'UTC' AS logged_at,
                      HOST(ip_address) AS ip_address,
                      filepath, filename, bytes, source
               FROM user_downloads
               WHERE username = %s
               ORDER BY logged_at DESC LIMIT %s""",
            (username, limit),
        )
    return [_ser(r) for r in rows]


def get_user_download_stats(
    date_from: Optional[str] = None, date_to: Optional[str] = None,
    sort_files_by: str = "downloads", sort_users_by: str = "downloads",
    source: Optional[str] = None,
    exclude_username: Optional[str] = None,
    username_exact: Optional[str] = None,
) -> dict:
    sort_files_by = sort_files_by if sort_files_by in ("downloads", "bytes") else "downloads"
    sort_users_by = sort_users_by if sort_users_by in ("downloads", "bytes") else "downloads"

    def _compute():
        where, params = _where(date_from=date_from, date_to=date_to, source=source,
                               exclude_username=exclude_username, username_exact=username_exact)
        with _conn() as conn:
            agg = _q1(conn,
                f"""SELECT COUNT(*) AS total,
                           COUNT(DISTINCT username) AS unique_users,
                           COUNT(DISTINCT ip_address) AS unique_ips,
                           COUNT(DISTINCT filepath) AS unique_files,
                           COALESCE(SUM(bytes), 0) AS total_bytes
                    FROM user_downloads{where}""", params)
            top_files = _q(conn,
                f"""SELECT filepath, filename,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM user_downloads{where}
                    GROUP BY filepath, filename
                    ORDER BY {sort_files_by} DESC LIMIT 10""", params)
            top_users = _q(conn,
                f"""SELECT username,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM user_downloads{where}
                    GROUP BY username
                    ORDER BY {sort_users_by} DESC LIMIT 10""", params)
            top_ips = _q(conn,
                f"""SELECT HOST(ip_address) AS ip_address,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM user_downloads{where}
                    GROUP BY ip_address ORDER BY downloads DESC LIMIT 10""", params)
        return {
            "total": agg["total"], "unique_users": agg["unique_users"],
            "unique_ips": agg["unique_ips"], "unique_files": agg["unique_files"],
            "total_bytes": agg["total_bytes"],
            "top_files": [dict(r) for r in top_files],
            "top_users": [dict(r) for r in top_users],
            "top_ips":   [dict(r) for r in top_ips],
        }

    if date_from or date_to:
        return _compute()
    ck = f"user_stats:{source or ''}:{sort_files_by}:{sort_users_by}:{exclude_username or ''}:{username_exact or ''}"
    return _swr(ck, _compute)


def get_user_download_timeline(days: int = 30, bucket: str = "day", source: Optional[str] = None) -> list:
    bucket = bucket if bucket in ("hour", "day", "week") else "day"

    def _compute():
        reg_from = _registered_downloads_sql(source)
        with _conn() as conn:
            rows = _q(conn,
                f"""SELECT date_trunc(%s, logged_at) AS bucket,
                           COUNT(*) AS downloads, COALESCE(SUM(bytes), 0) AS bytes
                    FROM {reg_from}
                    AND logged_at >= NOW() - (%s * INTERVAL '1 day')
                    GROUP BY bucket ORDER BY bucket ASC""",
                [bucket, days])
        return [_ser(r) for r in rows]

    ck = f"user_tl:{days}:{bucket}:{source or ''}"
    return _swr(ck, _compute)


def get_user_download_breakdown(days: int = 30, sort_by: str = "downloads", source: Optional[str] = None) -> list:
    sort_by = sort_by if sort_by in ("downloads", "bytes") else "downloads"

    def _compute():
        reg_from = _registered_downloads_sql(source)
        with _conn() as conn:
            rows = _q(conn,
                f"""SELECT username, COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM {reg_from}
                    AND logged_at >= NOW() - (%s * INTERVAL '1 day')
                    GROUP BY username ORDER BY {sort_by} DESC LIMIT 25""",
                [days])
        return [dict(r) for r in rows]

    ck = f"user_bd:{days}:{sort_by}:{source or ''}"
    return _swr(ck, _compute)


def export_user_downloads_csv(
    username: Optional[str] = None, ip: Optional[str] = None,
    filename: Optional[str] = None, date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> str:
    where, params = _where(username=username, ip=ip, filename=filename,
                           date_from=date_from, date_to=date_to)
    with _conn() as conn:
        rows = _q(conn,
            f"""SELECT logged_at AT TIME ZONE 'UTC' AS logged_at,
                       HOST(ip_address) AS ip_address,
                       username, filepath, filename, bytes, source
                FROM user_downloads{where}
                ORDER BY logged_at DESC LIMIT 100000""", params)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "ip_address", "username", "filepath", "filename", "bytes", "source"])
    for r in rows:
        w.writerow([r["logged_at"], r["ip_address"], r["username"],
                    r["filepath"], r["filename"], r["bytes"], r["source"]])
    return buf.getvalue()


# ── Anon downloads ────────────────────────────────────────────────────────────

def get_anon_downloads(
    page: int = 1, limit: int = 100,
    ip: Optional[str] = None, filename: Optional[str] = None,
    date_from: Optional[str] = None, date_to: Optional[str] = None,
    source: Optional[str] = None,
) -> dict:
    limit  = min(limit, 500)
    offset = (page - 1) * limit
    where, params = _where(ip=ip, filename=filename,
                           date_from=date_from, date_to=date_to, source=source)
    with _conn() as conn:
        total = _q1(conn, f"SELECT COUNT(*) AS n FROM anon_downloads{where}", params)["n"]
        rows  = _q(conn,
            f"""SELECT id, logged_at AT TIME ZONE 'UTC' AS logged_at,
                       HOST(ip_address) AS ip_address,
                       filepath, filename, bytes, source
                FROM anon_downloads{where}
                ORDER BY logged_at DESC LIMIT %s OFFSET %s""",
            params + [limit, offset],
        )
    return {
        "total": total, "page": page, "limit": limit,
        "pages": max(1, -(-total // limit)),
        "rows": [_ser(r) for r in rows],
    }


def get_anon_download_stats(
    date_from: Optional[str] = None, date_to: Optional[str] = None,
    sort_files_by: str = "downloads",
    source: Optional[str] = None,
) -> dict:
    sort_files_by = sort_files_by if sort_files_by in ("downloads", "bytes") else "downloads"

    def _compute():
        where, params = _where(date_from=date_from, date_to=date_to, source=source)
        with _conn() as conn:
            agg = _q1(conn,
                f"""SELECT COUNT(*) AS total,
                           COUNT(DISTINCT ip_address) AS unique_ips,
                           COUNT(DISTINCT filepath) AS unique_files,
                           COALESCE(SUM(bytes), 0) AS total_bytes
                    FROM anon_downloads{where}""", params)
            top_files = _q(conn,
                f"""SELECT filepath, filename,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM anon_downloads{where}
                    GROUP BY filepath, filename
                    ORDER BY {sort_files_by} DESC LIMIT 10""", params)
            top_ips = _q(conn,
                f"""SELECT HOST(ip_address) AS ip_address,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM anon_downloads{where}
                    GROUP BY ip_address ORDER BY downloads DESC LIMIT 10""", params)
        return {
            "total": agg["total"], "unique_ips": agg["unique_ips"],
            "unique_files": agg["unique_files"],
            "total_bytes": agg["total_bytes"],
            "top_files": [dict(r) for r in top_files],
            "top_ips":   [dict(r) for r in top_ips],
        }

    if date_from or date_to:
        return _compute()
    ck = f"anon_stats:{source or ''}:{sort_files_by}"
    return _swr(ck, _compute)


def get_anon_download_timeline(days: int = 30, bucket: str = "day", source: Optional[str] = None) -> list:
    bucket = bucket if bucket in ("hour", "day", "week") else "day"

    def _compute():
        anon_from = _anon_downloads_sql(source)
        with _conn() as conn:
            rows = _q(conn,
                f"""SELECT date_trunc(%s, logged_at) AS bucket,
                           COUNT(*) AS downloads, COALESCE(SUM(bytes), 0) AS bytes
                    FROM {anon_from}
                    WHERE logged_at >= NOW() - (%s * INTERVAL '1 day')
                    GROUP BY bucket ORDER BY bucket ASC""",
                [bucket, days])
        return [_ser(r) for r in rows]

    ck = f"anon_tl:{days}:{bucket}:{source or ''}"
    return _swr(ck, _compute)


def export_anon_downloads_csv(
    ip: Optional[str] = None, filename: Optional[str] = None,
    date_from: Optional[str] = None, date_to: Optional[str] = None,
) -> str:
    where, params = _where(ip=ip, filename=filename,
                           date_from=date_from, date_to=date_to)
    with _conn() as conn:
        rows = _q(conn,
            f"""SELECT logged_at AT TIME ZONE 'UTC' AS logged_at,
                       HOST(ip_address) AS ip_address,
                       filepath, filename, bytes, source
                FROM anon_downloads{where}
                ORDER BY logged_at DESC LIMIT 100000""", params)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "ip_address", "filepath", "filename", "bytes", "source"])
    for r in rows:
        w.writerow([r["logged_at"], r["ip_address"],
                    r["filepath"], r["filename"], r["bytes"], r["source"]])
    return buf.getvalue()


# ── User uploads (FTP STOR/APPE) ────────────────────────────────────────────────

def get_user_uploads(
    page: int = 1, limit: int = 100,
    username: Optional[str] = None, ip: Optional[str] = None,
    filename: Optional[str] = None, date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> dict:
    limit  = min(limit, 500)
    offset = (page - 1) * limit
    where, params = _where(username=username, ip=ip, filename=filename,
                           date_from=date_from, date_to=date_to)
    with _conn() as conn:
        total = _q1(conn, f"SELECT COUNT(*) AS n FROM user_uploads{where}", params)["n"]
        rows  = _q(conn,
            f"""SELECT id, logged_at AT TIME ZONE 'UTC' AS logged_at,
                       HOST(ip_address) AS ip_address,
                       username, filepath, filename, bytes, source
                FROM user_uploads{where}
                ORDER BY logged_at DESC LIMIT %s OFFSET %s""",
            params + [limit, offset],
        )
    return {
        "total": total, "page": page, "limit": limit,
        "pages": max(1, -(-total // limit)),
        "rows": [_ser(r) for r in rows],
    }


def get_user_upload_stats(
    date_from: Optional[str] = None, date_to: Optional[str] = None,
    sort_files_by: str = "downloads", sort_users_by: str = "downloads",
) -> dict:
    sort_files_by = sort_files_by if sort_files_by in ("downloads", "bytes") else "downloads"
    sort_users_by = sort_users_by if sort_users_by in ("downloads", "bytes") else "downloads"

    def _compute():
        where, params = _where(date_from=date_from, date_to=date_to)
        with _conn() as conn:
            agg = _q1(conn,
                f"""SELECT COUNT(*) AS total,
                           COUNT(DISTINCT username) AS unique_users,
                           COUNT(DISTINCT ip_address) AS unique_ips,
                           COUNT(DISTINCT filepath) AS unique_files,
                           COALESCE(SUM(bytes), 0) AS total_bytes
                    FROM user_uploads{where}""", params)
            top_files = _q(conn,
                f"""SELECT filepath, filename,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM user_uploads{where}
                    GROUP BY filepath, filename
                    ORDER BY {sort_files_by} DESC LIMIT 10""", params)
            top_users = _q(conn,
                f"""SELECT username,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM user_uploads{where}
                    GROUP BY username
                    ORDER BY {sort_users_by} DESC LIMIT 10""", params)
            top_ips = _q(conn,
                f"""SELECT HOST(ip_address) AS ip_address,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM user_uploads{where}
                    GROUP BY ip_address ORDER BY downloads DESC LIMIT 10""", params)
        return {
            "total": agg["total"], "unique_users": agg["unique_users"],
            "unique_ips": agg["unique_ips"], "unique_files": agg["unique_files"],
            "total_bytes": agg["total_bytes"],
            "top_files": [dict(r) for r in top_files],
            "top_users": [dict(r) for r in top_users],
            "top_ips":   [dict(r) for r in top_ips],
        }

    if date_from or date_to:
        return _compute()
    ck = f"user_upload_stats:{sort_files_by}:{sort_users_by}"
    return _swr(ck, _compute)


def get_upload_timeline(days: int = 30, bucket: str = "day") -> list:
    bucket = bucket if bucket in ("hour", "day", "week") else "day"

    def _compute():
        with _conn() as conn:
            rows = _q(conn,
                f"""SELECT date_trunc(%s, logged_at) AS bucket,
                           COUNT(*) AS downloads, COALESCE(SUM(bytes), 0) AS bytes
                    FROM user_uploads
                    WHERE logged_at >= NOW() - (%s * INTERVAL '1 day')
                    GROUP BY bucket ORDER BY bucket ASC""",
                [bucket, days])
        return [_ser(r) for r in rows]

    ck = f"upload_tl:{days}:{bucket}"
    return _swr(ck, _compute)


def export_user_uploads_csv(
    username: Optional[str] = None, ip: Optional[str] = None,
    filename: Optional[str] = None, date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> str:
    where, params = _where(username=username, ip=ip, filename=filename,
                           date_from=date_from, date_to=date_to)
    with _conn() as conn:
        rows = _q(conn,
            f"""SELECT logged_at AT TIME ZONE 'UTC' AS logged_at,
                       HOST(ip_address) AS ip_address,
                       username, filepath, filename, bytes, source
                FROM user_uploads{where}
                ORDER BY logged_at DESC LIMIT 100000""", params)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "ip_address", "username", "filepath", "filename", "bytes", "source"])
    for r in rows:
        w.writerow([r["logged_at"], r["ip_address"], r["username"],
                    r["filepath"], r["filename"], r["bytes"], r["source"]])
    return buf.getvalue()


# ── Anon uploads ─────────────────────────────────────────────────────────────

def get_anon_uploads(
    page: int = 1, limit: int = 100,
    ip: Optional[str] = None, filename: Optional[str] = None,
    date_from: Optional[str] = None, date_to: Optional[str] = None,
) -> dict:
    limit  = min(limit, 500)
    offset = (page - 1) * limit
    where, params = _where(ip=ip, filename=filename,
                           date_from=date_from, date_to=date_to)
    with _conn() as conn:
        total = _q1(conn, f"SELECT COUNT(*) AS n FROM anon_uploads{where}", params)["n"]
        rows  = _q(conn,
            f"""SELECT id, logged_at AT TIME ZONE 'UTC' AS logged_at,
                       HOST(ip_address) AS ip_address,
                       filepath, filename, bytes, source
                FROM anon_uploads{where}
                ORDER BY logged_at DESC LIMIT %s OFFSET %s""",
            params + [limit, offset],
        )
    return {
        "total": total, "page": page, "limit": limit,
        "pages": max(1, -(-total // limit)),
        "rows": [_ser(r) for r in rows],
    }


def get_anon_upload_stats(
    date_from: Optional[str] = None, date_to: Optional[str] = None,
    sort_files_by: str = "downloads",
) -> dict:
    sort_files_by = sort_files_by if sort_files_by in ("downloads", "bytes") else "downloads"

    def _compute():
        where, params = _where(date_from=date_from, date_to=date_to)
        with _conn() as conn:
            agg = _q1(conn,
                f"""SELECT COUNT(*) AS total,
                           COUNT(DISTINCT ip_address) AS unique_ips,
                           COUNT(DISTINCT filepath) AS unique_files,
                           COALESCE(SUM(bytes), 0) AS total_bytes
                    FROM anon_uploads{where}""", params)
            top_files = _q(conn,
                f"""SELECT filepath, filename,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM anon_uploads{where}
                    GROUP BY filepath, filename
                    ORDER BY {sort_files_by} DESC LIMIT 10""", params)
            top_ips = _q(conn,
                f"""SELECT HOST(ip_address) AS ip_address,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM anon_uploads{where}
                    GROUP BY ip_address ORDER BY downloads DESC LIMIT 10""", params)
        return {
            "total": agg["total"], "unique_ips": agg["unique_ips"],
            "unique_files": agg["unique_files"],
            "total_bytes": agg["total_bytes"],
            "top_files": [dict(r) for r in top_files],
            "top_ips":   [dict(r) for r in top_ips],
        }

    if date_from or date_to:
        return _compute()
    ck = f"anon_upload_stats:{sort_files_by}"
    return _swr(ck, _compute)


def export_anon_uploads_csv(
    ip: Optional[str] = None, filename: Optional[str] = None,
    date_from: Optional[str] = None, date_to: Optional[str] = None,
) -> str:
    where, params = _where(ip=ip, filename=filename,
                           date_from=date_from, date_to=date_to)
    with _conn() as conn:
        rows = _q(conn,
            f"""SELECT logged_at AT TIME ZONE 'UTC' AS logged_at,
                       HOST(ip_address) AS ip_address,
                       filepath, filename, bytes, source
                FROM anon_uploads{where}
                ORDER BY logged_at DESC LIMIT 100000""", params)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "ip_address", "filepath", "filename", "bytes", "source"])
    for r in rows:
        w.writerow([r["logged_at"], r["ip_address"],
                    r["filepath"], r["filename"], r["bytes"], r["source"]])
    return buf.getvalue()


# ── Earliest available activity (for "Max" quick-range) ───────────────────────

def get_earliest_activity(source: Optional[str] = None) -> dict:
    """Earliest logged_at across the effective registered+anon dataset for a
    source scope, plus how many days back from now that is — lets the
    frontend's "Max" quick-range button reach exactly as far back as the data
    actually goes, rather than a guessed constant.
    """
    def _compute():
        reg_from = _registered_downloads_sql(source)
        anon_from = _anon_downloads_sql(source)
        with _conn() as conn:
            reg_row = _q1(conn, f"SELECT MIN(logged_at) AS m FROM {reg_from}")
            anon_row = _q1(conn, f"SELECT MIN(logged_at) AS m FROM {anon_from}")
        candidates = [r["m"] for r in (reg_row, anon_row) if r and r["m"] is not None]
        if not candidates:
            return {"earliest": None, "days": 30}
        earliest = min(candidates)
        days = (datetime.now(timezone.utc) - earliest).days + 1
        return {"earliest": earliest.isoformat(), "days": max(days, 1)}

    ck = f"earliest:{source or ''}"
    return _swr(ck, _compute)


# ── Combined summary ──────────────────────────────────────────────────────────

def get_summary(days: int = 30, source: Optional[str] = None) -> dict:
    def _compute():
        reg_from  = _registered_downloads_sql(source)
        anon_from = _anon_downloads_sql(source)

        # 8 subqueries in order: user_dl_cur, user_dl_prev, user_bytes_cur, user_bytes_prev,
        #                        anon_dl_cur,  anon_dl_prev,  anon_bytes_cur,  anon_bytes_prev
        p_c = [days]
        p_p = [days * 2, days]
        summary_params = p_c + p_p + p_c + p_p + p_c + p_p + p_c + p_p

        with _conn() as conn:
            cur = _q1(conn, f"""
                SELECT
                  (SELECT COUNT(*) FROM {reg_from}
                   AND logged_at >= NOW() - (%s * INTERVAL '1 day')) AS user_dl_cur,
                  (SELECT COUNT(*) FROM {reg_from}
                   AND logged_at >= NOW() - (%s * INTERVAL '1 day')
                   AND logged_at <  NOW() - (%s * INTERVAL '1 day')) AS user_dl_prev,
                  (SELECT COALESCE(SUM(bytes),0) FROM {reg_from}
                   AND logged_at >= NOW() - (%s * INTERVAL '1 day')) AS user_bytes_cur,
                  (SELECT COALESCE(SUM(bytes),0) FROM {reg_from}
                   AND logged_at >= NOW() - (%s * INTERVAL '1 day')
                   AND logged_at <  NOW() - (%s * INTERVAL '1 day')) AS user_bytes_prev,
                  (SELECT COUNT(*) FROM {anon_from}
                   WHERE logged_at >= NOW() - (%s * INTERVAL '1 day')) AS anon_dl_cur,
                  (SELECT COUNT(*) FROM {anon_from}
                   WHERE logged_at >= NOW() - (%s * INTERVAL '1 day')
                     AND logged_at <  NOW() - (%s * INTERVAL '1 day')) AS anon_dl_prev,
                  (SELECT COALESCE(SUM(bytes),0) FROM {anon_from}
                   WHERE logged_at >= NOW() - (%s * INTERVAL '1 day')) AS anon_bytes_cur,
                  (SELECT COALESCE(SUM(bytes),0) FROM {anon_from}
                   WHERE logged_at >= NOW() - (%s * INTERVAL '1 day')
                     AND logged_at <  NOW() - (%s * INTERVAL '1 day')) AS anon_bytes_prev
            """, summary_params)
            timeline = _q(conn, f"""
                SELECT bucket,
                       SUM(user_dl) AS user_downloads,
                       SUM(anon_dl) AS anon_downloads,
                       SUM(total_bytes) AS bytes
                FROM (
                    SELECT date_trunc('day', logged_at) AS bucket,
                           COUNT(*) AS user_dl, 0 AS anon_dl,
                           COALESCE(SUM(bytes), 0) AS total_bytes
                    FROM {reg_from}
                    AND logged_at >= NOW() - (%s * INTERVAL '1 day')
                    GROUP BY bucket
                    UNION ALL
                    SELECT date_trunc('day', logged_at) AS bucket,
                           0 AS user_dl, COUNT(*) AS anon_dl,
                           COALESCE(SUM(bytes), 0) AS total_bytes
                    FROM {anon_from}
                    WHERE logged_at >= NOW() - (%s * INTERVAL '1 day')
                    GROUP BY bucket
                ) sub
                GROUP BY bucket ORDER BY bucket ASC
            """, [days, days])

        def pct(c, p):
            return round(((c - p) / p) * 100, 1) if p else None

        return {
            "days": days,
            "user_downloads":  {"current": cur["user_dl_cur"],    "previous": cur["user_dl_prev"],    "change": pct(cur["user_dl_cur"],    cur["user_dl_prev"])},
            "user_bytes":      {"current": cur["user_bytes_cur"], "previous": cur["user_bytes_prev"], "change": pct(cur["user_bytes_cur"], cur["user_bytes_prev"])},
            "anon_downloads":  {"current": cur["anon_dl_cur"],    "previous": cur["anon_dl_prev"],    "change": pct(cur["anon_dl_cur"],    cur["anon_dl_prev"])},
            "anon_bytes":      {"current": cur["anon_bytes_cur"], "previous": cur["anon_bytes_prev"], "change": pct(cur["anon_bytes_cur"], cur["anon_bytes_prev"])},
            "timeline": [_ser(r) for r in timeline],
        }

    ck = f"summary:{days}:{source or ''}"
    return _swr(ck, _compute)
