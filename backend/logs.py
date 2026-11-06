"""
backend/logs.py

Read-only PostgreSQL access for FTP/HTTP download activity logs.
Connects to the separate db_logs container.
Also reads/writes tailer_config for settings and status.
"""

import csv
import functools
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
_POOL_MAX = 10
_POOL_WAIT_SECONDS = 20
_pool: psycopg2.pool.ThreadedConnectionPool | None = None
# getconn() raises immediately when the pool is empty. Requests queue here
# instead, so a burst (one public overview refresh alone is 7 parallel requests)
# waits a moment rather than failing with a 503, admin routes included.
_pool_slots = threading.BoundedSemaphore(_POOL_MAX)


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            1, _POOL_MAX,
            settings.logs_database_url,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
    return _pool


class _Ctx:
    def __enter__(self):
        if not _pool_slots.acquire(timeout=_POOL_WAIT_SECONDS):
            raise psycopg2.pool.PoolError("timed out waiting for a connection")
        try:
            self.c = _get_pool().getconn()
        except Exception:
            _pool_slots.release()
            raise
        return self.c
    def __exit__(self, *_):
        _get_pool().putconn(self.c)
        _pool_slots.release()


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

# TTL scales with the window a key covers: a few new rows barely move a
# 1-year or all-time aggregate, but recomputing one scans millions of rows.
_TTL_ALL_TIME = 3600
_TTL_SHORT = 300  # the upload tables are tiny; refreshing them is cheap


def _ttl_for_days(days: int) -> int:
    if days <= 1:
        return 300
    if days <= 7:
        return 600
    if days <= 30:
        return 900
    if days <= 90:
        return 1800
    return _TTL_ALL_TIME


# Sub-day windows the public overview offers: window minutes -> timeline bucket
# seconds. A fixed set, since these routes are public and each value is a cache
# key. Cheap (0.1s at 12h) but meaningless if stale, so they use a very short
# TTL and never serve an expired value (see _cached_fresh).
MINUTE_WINDOWS = {1: 5, 5: 15, 60: 60, 720: 900}


def _ttl_for_minutes(minutes: int) -> int:
    if minutes <= 5:
        return 5
    if minutes <= 60:
        return 30
    return 120


def _window_key(days: Optional[int], minutes: Optional[int]) -> str:
    return f"m{minutes}" if minutes else str(days)


def _bucket_sql(bucket: str, minutes: Optional[int]) -> tuple[str, object]:
    """(SQL expression, its parameter) for a timeline's bucket column."""
    if minutes:
        return "date_bin(%s * INTERVAL '1 second', logged_at, TIMESTAMPTZ 'epoch')", MINUTE_WINDOWS[minutes]
    return "date_trunc(%s, logged_at)", bucket


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


def _cache_get_any(key: str, ttl: int):
    """Look up a cache row regardless of age.

    Returns (data, is_fresh): data is None if nothing has ever been computed
    for this key; is_fresh is True while inside the TTL window (seconds).
    """
    try:
        _ensure_cache_table()
        with _conn() as conn:
            row = _q1(conn,
                "SELECT data, (computed_at > NOW() - %s * INTERVAL '1 second') AS is_fresh "
                "FROM stats_cache WHERE cache_key = %s",
                (ttl, key))
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
# always hand back the last computed value immediately (even past its TTL) and
# kick off a background refresh; only a key that has *never* been computed
# pays the synchronous cost.
#
# At most _BG_SLOTS refreshes run at once; the rest wait their turn. Without
# this, a page load touching dozens of stale keys fired them all in parallel,
# exhausted the connection pool (failing ordinary admin requests), and a
# minutes-long compute whose _cache_set then couldn't get a connection was
# thrown away and redone on the next read — indefinitely.

_BG_SLOTS = 2
_bg_slots = threading.BoundedSemaphore(_BG_SLOTS)
_bg_inflight: set[str] = set()
_bg_inflight_lock = threading.Lock()


def _refresh_in_background(key: str, compute):
    with _bg_inflight_lock:
        if key in _bg_inflight:
            return  # a refresh for this key is already running or queued
        _bg_inflight.add(key)

    def _run():
        try:
            with _bg_slots:
                _cache_set(key, compute())
        except Exception:
            pass
        finally:
            with _bg_inflight_lock:
                _bg_inflight.discard(key)

    threading.Thread(target=_run, daemon=True, name=f"stats-refresh:{key}").start()


def _swr(key: str, compute, ttl: int):
    data, fresh = _cache_get_any(key, ttl)
    if data is not None:
        if not fresh:
            _refresh_in_background(key, compute)
        return data
    result = compute()
    _cache_set(key, result)
    return result


_fresh_locks: dict[str, threading.Lock] = {}


def _cached_fresh(key: str, compute, ttl: int):
    """For minute windows, where an expired value is simply wrong: recompute in
    the request, one at a time per key so concurrent viewers share one query."""
    data, fresh = _cache_get_any(key, ttl)
    if fresh:
        return data
    with _fresh_locks.setdefault(key, threading.Lock()):
        data, fresh = _cache_get_any(key, ttl)
        if fresh:
            return data
        result = compute()
        _cache_set(key, result)
        return result


def _swr_window(key: str, compute, days: Optional[int], minutes: Optional[int]):
    if minutes:
        return _cached_fresh(key, compute, _ttl_for_minutes(minutes))
    return _swr(key, compute, _ttl_for_days(days))


def warmup_stats_cache():
    """Pre-compute common stats combinations so page loads are instant.

    Called once at startup. Cached keys survive restarts, so for them this
    only queues a (rate-limited) background refresh if they're stale; only
    never-computed keys are computed synchronously here.
    """
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
    # Heatmaps: one all-history hourly series per source/kind serves every range.
    for source, kind in (("ftp", "downloads"), ("http", "downloads"), ("ftp", "uploads"), ("ftp", "uploads_public")):
        try:
            _heat_series_all(source, kind)
        except Exception:
            pass
    # Last: the public overview's windowed Top Files/IPs. A cold 1y compute
    # takes about a minute, past nginx's 30s proxy timeout, so it can't be left to the
    # first click.
    for days in (1, 7, 30, 365):
        try:
            get_user_download_stats(days=days)
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


_WINDOW_COLS = ("n_groups", "total", "total_bytes")


def _window_val(rows: list, col: str) -> int:
    """A window-function column (identical on every row) from a top-N
    result; 0 when the filtered set is empty."""
    return int(rows[0][col] or 0) if rows else 0


def _strip_window(rows: list) -> list[dict]:
    return [{k: v for k, v in r.items() if k not in _WINDOW_COLS} for r in rows]


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
    days: Optional[int] = None,
    minutes: Optional[int] = None,
) -> dict:
    span = minutes or (days * 1440 if days else None)
    sort_files_by = sort_files_by if sort_files_by in ("downloads", "bytes") else "downloads"
    sort_users_by = sort_users_by if sort_users_by in ("downloads", "bytes") else "downloads"

    def _compute():
        where, params = _where(date_from=date_from, date_to=date_to, source=source,
                               exclude_username=exclude_username, username_exact=username_exact)
        if span:
            where += (" AND " if where else " WHERE ") + "logged_at >= NOW() - (%s * INTERVAL '1 minute')"
            params.append(span)
        # No separate COUNT(DISTINCT ...) pass: each GROUP BY below already
        # builds the distinct set, so a window count over its groups gives
        # the unique_* figure (filename is basename(filepath), so file groups
        # == distinct filepaths) and the window sums give total/total_bytes.
        # COUNT(DISTINCT) sorts every row and spilled GBs of temp files.
        with _conn() as conn:
            top_files = _q(conn,
                f"""SELECT filepath, filename,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes,
                           COUNT(*) OVER () AS n_groups
                    FROM user_downloads{where}
                    GROUP BY filepath, filename
                    ORDER BY {sort_files_by} DESC LIMIT 10""", params)
            top_users = _q(conn,
                f"""SELECT username,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes,
                           COUNT(*) OVER () AS n_groups,
                           SUM(COUNT(*)) OVER () AS total,
                           SUM(COALESCE(SUM(bytes), 0)) OVER () AS total_bytes
                    FROM user_downloads{where}
                    GROUP BY username
                    ORDER BY {sort_users_by} DESC LIMIT 10""", params)
            top_ips = _q(conn,
                f"""SELECT HOST(ip_address) AS ip_address,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes,
                           COUNT(*) OVER () AS n_groups
                    FROM user_downloads{where}
                    GROUP BY ip_address ORDER BY downloads DESC LIMIT 10""", params)
        return {
            "total": _window_val(top_users, "total"),
            "unique_users": _window_val(top_users, "n_groups"),
            "unique_ips": _window_val(top_ips, "n_groups"),
            "unique_files": _window_val(top_files, "n_groups"),
            "total_bytes": _window_val(top_users, "total_bytes"),
            "top_files": _strip_window(top_files),
            "top_users": _strip_window(top_users),
            "top_ips":   _strip_window(top_ips),
        }

    if date_from or date_to:
        return _compute()
    ck = f"user_stats:{source or ''}:{sort_files_by}:{sort_users_by}:{exclude_username or ''}:{username_exact or ''}"
    if span:
        return _swr_window(f"{ck}:{_window_key(days, minutes)}", _compute, days, minutes)
    return _swr(ck, _compute, _TTL_ALL_TIME)


def get_user_download_timeline(days: int = 30, bucket: str = "day", source: Optional[str] = None,
                               minutes: Optional[int] = None) -> list:
    bucket = bucket if bucket in ("hour", "day", "week") else "day"
    span = minutes or days * 1440

    def _compute():
        reg_from = _registered_downloads_sql(source)
        bucket_expr, bucket_arg = _bucket_sql(bucket, minutes)
        with _conn() as conn:
            rows = _q(conn,
                f"""SELECT {bucket_expr} AS bucket,
                           COUNT(*) AS downloads, COALESCE(SUM(bytes), 0) AS bytes
                    FROM {reg_from}
                    AND logged_at >= NOW() - (%s * INTERVAL '1 minute')
                    GROUP BY bucket ORDER BY bucket ASC""",
                [bucket_arg, span])
        return [_ser(r) for r in rows]

    ck = f"user_tl:{_window_key(days, minutes)}:{bucket}:{source or ''}"
    return _swr_window(ck, _compute, days, minutes)


def get_user_download_breakdown(days: int = 30, sort_by: str = "downloads", source: Optional[str] = None,
                                minutes: Optional[int] = None) -> list:
    sort_by = sort_by if sort_by in ("downloads", "bytes") else "downloads"
    span = minutes or days * 1440

    def _compute():
        reg_from = _registered_downloads_sql(source)
        with _conn() as conn:
            rows = _q(conn,
                f"""SELECT username, COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes
                    FROM {reg_from}
                    AND logged_at >= NOW() - (%s * INTERVAL '1 minute')
                    GROUP BY username ORDER BY {sort_by} DESC LIMIT 25""",
                [span])
        return [dict(r) for r in rows]

    ck = f"user_bd:{_window_key(days, minutes)}:{sort_by}:{source or ''}"
    return _swr_window(ck, _compute, days, minutes)


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
        # Distinct counts and totals come from window functions over the
        # GROUP BYs — see get_user_download_stats.
        with _conn() as conn:
            top_files = _q(conn,
                f"""SELECT filepath, filename,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes,
                           COUNT(*) OVER () AS n_groups
                    FROM anon_downloads{where}
                    GROUP BY filepath, filename
                    ORDER BY {sort_files_by} DESC LIMIT 10""", params)
            top_ips = _q(conn,
                f"""SELECT HOST(ip_address) AS ip_address,
                           COUNT(*) AS downloads,
                           COALESCE(SUM(bytes), 0) AS bytes,
                           COUNT(*) OVER () AS n_groups,
                           SUM(COUNT(*)) OVER () AS total,
                           SUM(COALESCE(SUM(bytes), 0)) OVER () AS total_bytes
                    FROM anon_downloads{where}
                    GROUP BY ip_address ORDER BY downloads DESC LIMIT 10""", params)
        return {
            "total": _window_val(top_ips, "total"),
            "unique_ips": _window_val(top_ips, "n_groups"),
            "unique_files": _window_val(top_files, "n_groups"),
            "total_bytes": _window_val(top_ips, "total_bytes"),
            "top_files": _strip_window(top_files),
            "top_ips":   _strip_window(top_ips),
        }

    if date_from or date_to:
        return _compute()
    ck = f"anon_stats:{source or ''}:{sort_files_by}"
    return _swr(ck, _compute, _TTL_ALL_TIME)


def get_anon_download_timeline(days: int = 30, bucket: str = "day", source: Optional[str] = None,
                               minutes: Optional[int] = None) -> list:
    bucket = bucket if bucket in ("hour", "day", "week") else "day"
    span = minutes or days * 1440

    def _compute():
        anon_from = _anon_downloads_sql(source)
        bucket_expr, bucket_arg = _bucket_sql(bucket, minutes)
        with _conn() as conn:
            rows = _q(conn,
                f"""SELECT {bucket_expr} AS bucket,
                           COUNT(*) AS downloads, COALESCE(SUM(bytes), 0) AS bytes
                    FROM {anon_from}
                    WHERE logged_at >= NOW() - (%s * INTERVAL '1 minute')
                    GROUP BY bucket ORDER BY bucket ASC""",
                [bucket_arg, span])
        return [_ser(r) for r in rows]

    ck = f"anon_tl:{_window_key(days, minutes)}:{bucket}:{source or ''}"
    return _swr_window(ck, _compute, days, minutes)


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
    return _swr(ck, _compute, _TTL_SHORT)


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
    return _swr(ck, _compute, _TTL_SHORT)


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
    return _swr(ck, _compute, _TTL_SHORT)


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
    return _swr(ck, _compute, _TTL_ALL_TIME)


# ── Combined summary ──────────────────────────────────────────────────────────

def get_summary(days: int = 30, source: Optional[str] = None, minutes: Optional[int] = None) -> dict:
    span = minutes or days * 1440

    def _compute():
        reg_from  = _registered_downloads_sql(source)
        anon_from = _anon_downloads_sql(source)

        # 8 subqueries in order: user_dl_cur, user_dl_prev, user_bytes_cur, user_bytes_prev,
        #                        anon_dl_cur,  anon_dl_prev,  anon_bytes_cur,  anon_bytes_prev
        p_c = [span]
        p_p = [span * 2, span]
        summary_params = p_c + p_p + p_c + p_p + p_c + p_p + p_c + p_p

        with _conn() as conn:
            cur = _q1(conn, f"""
                SELECT
                  (SELECT COUNT(*) FROM {reg_from}
                   AND logged_at >= NOW() - (%s * INTERVAL '1 minute')) AS user_dl_cur,
                  (SELECT COUNT(*) FROM {reg_from}
                   AND logged_at >= NOW() - (%s * INTERVAL '1 minute')
                   AND logged_at <  NOW() - (%s * INTERVAL '1 minute')) AS user_dl_prev,
                  (SELECT COALESCE(SUM(bytes),0) FROM {reg_from}
                   AND logged_at >= NOW() - (%s * INTERVAL '1 minute')) AS user_bytes_cur,
                  (SELECT COALESCE(SUM(bytes),0) FROM {reg_from}
                   AND logged_at >= NOW() - (%s * INTERVAL '1 minute')
                   AND logged_at <  NOW() - (%s * INTERVAL '1 minute')) AS user_bytes_prev,
                  (SELECT COUNT(*) FROM {anon_from}
                   WHERE logged_at >= NOW() - (%s * INTERVAL '1 minute')) AS anon_dl_cur,
                  (SELECT COUNT(*) FROM {anon_from}
                   WHERE logged_at >= NOW() - (%s * INTERVAL '1 minute')
                     AND logged_at <  NOW() - (%s * INTERVAL '1 minute')) AS anon_dl_prev,
                  (SELECT COALESCE(SUM(bytes),0) FROM {anon_from}
                   WHERE logged_at >= NOW() - (%s * INTERVAL '1 minute')) AS anon_bytes_cur,
                  (SELECT COALESCE(SUM(bytes),0) FROM {anon_from}
                   WHERE logged_at >= NOW() - (%s * INTERVAL '1 minute')
                     AND logged_at <  NOW() - (%s * INTERVAL '1 minute')) AS anon_bytes_prev
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
                    AND logged_at >= NOW() - (%s * INTERVAL '1 minute')
                    GROUP BY bucket
                    UNION ALL
                    SELECT date_trunc('day', logged_at) AS bucket,
                           0 AS user_dl, COUNT(*) AS anon_dl,
                           COALESCE(SUM(bytes), 0) AS total_bytes
                    FROM {anon_from}
                    WHERE logged_at >= NOW() - (%s * INTERVAL '1 minute')
                    GROUP BY bucket
                ) sub
                GROUP BY bucket ORDER BY bucket ASC
            """, [span, span])

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

    ck = f"summary:{_window_key(days, minutes)}:{source or ''}"
    return _swr_window(ck, _compute, days, minutes)


# ── Activity heatmap (day-of-week × hour-of-day) ──────────────────────────────
# All downloads for one source (registered + anonymous — no split, so the
# _registered/_anon helpers aren't needed), folded into a 7×24 grid in the
# viewer's timezone for any range (presets or a custom start/end).
#
# One cached, timezone-independent scan per source: every UTC hour bucket
# (epoch hours) of all history, plus the hour it was computed. Requests slice
# that series in Python, so arbitrary ranges cost nothing extra, and top it up
# with a live query (micro-cached) for hours since the scan, so recent hours
# are never stale even though the full scan (~20s for HTTP) refreshes rarely.

_HEAT_TTL = 6 * 3600
_HEAT_TAIL_TTL = 60

_HEAT_SQL = """
    SELECT h, SUM(n) AS n, SUM(b) AS b FROM (
        SELECT floor(extract(epoch FROM logged_at) / 3600)::bigint AS h,
               COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b
        FROM user_{table} WHERE source = %s {cond} {user_cond}
        GROUP BY h
        UNION ALL
        SELECT floor(extract(epoch FROM logged_at) / 3600)::bigint AS h,
               COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b
        FROM anon_{table} WHERE source = %s {cond}
        GROUP BY h
    ) s GROUP BY h ORDER BY h
"""


# kind -> (user_/anon_ table suffix, extra filter on the user_ table). Whitelisted,
# embedded in SQL. "uploads_public" backs the public route: it drops private
# users' uploads (their activity stays off public routes). ftp_activity_users
# is the backend-published trusted/private username list in db_logs.
HEAT_KINDS = {
    "downloads": ("downloads", ""),
    "uploads": ("uploads", ""),
    "uploads_public": ("uploads", "AND username NOT IN "
                       "(SELECT username FROM ftp_activity_users WHERE user_class = 'private')"),
}


def _heat_rows(source: str, kind: str, since_h: Optional[int] = None) -> list:
    assert kind in HEAT_KINDS
    cond, extra = "", []
    if since_h is not None:
        cond, extra = "AND logged_at >= to_timestamp(%s)", [since_h * 3600]
    with _conn() as conn:
        table, user_cond = HEAT_KINDS[kind]
        rows = _q(conn, _HEAT_SQL.format(cond=cond, table=table, user_cond=user_cond), [source, *extra, source, *extra])
    return [[int(r["h"]), int(r["n"]), int(r["b"])] for r in rows]


def _heat_series_all(source: str, kind: str) -> dict:
    def _compute():
        computed_h = int(datetime.now(timezone.utc).timestamp() // 3600)
        return {"computed_h": computed_h, "rows": _heat_rows(source, kind)}
    return _swr(f"heat_all:{kind}:{source}", _compute, _HEAT_TTL)


def _heat_series(source: str, kind: str) -> dict[int, tuple[int, int]]:
    """{epoch_hour: (transfers, bytes)} for all history, current to the minute."""
    base = _heat_series_all(source, kind)
    cut = int(base["computed_h"])
    tail = _cached_fresh(f"heat_tail:{kind}:{source}:{cut}", lambda: _heat_rows(source, kind, cut), _HEAT_TAIL_TTL)
    series = {h: (n, b) for h, n, b in base["rows"] if h < cut}
    series.update({h: (n, b) for h, n, b in tail})
    return series


@functools.lru_cache(maxsize=1)
def _known_zones() -> frozenset:
    from zoneinfo import available_timezones  # scans the tzdata tree; once
    return frozenset(available_timezones())


def _zone(tz: Optional[str]):
    from zoneinfo import ZoneInfo
    if tz and tz in _known_zones():
        try:
            return tz, ZoneInfo(tz)
        except Exception:
            pass
    return "UTC", timezone.utc


def get_activity_heatmap(source: str, tz: Optional[str] = None, days: Optional[int] = None,
                         start: Optional[datetime] = None, end: Optional[datetime] = None,
                         kind: str = "downloads") -> dict:
    """Transfers (`kind` = downloads or uploads) and bytes per (weekday, hour) in `tz`; rows are Monday..Sunday.

    Range: `start`/`end` (custom; `end` defaults to now), else the last `days`,
    else all history. Whole hours: an hour is included if the range touches it.
    `slots[d][h]` is how many times that weekday/hour occurred in the range
    (from the first hour with data, if later) — the frontend divides by it for
    a per-hour average, so cells stay comparable whatever the range.
    """
    tz_name, zone = _zone(tz)
    series = _heat_series(source, kind)
    now_h = int(datetime.now(timezone.utc).timestamp() // 3600)
    first_h = min(series) if series else now_h

    def _ts(dt: datetime) -> float:
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()

    end_h = now_h if end is None else min(now_h, -int(-_ts(end) // 3600) - 1)  # ceil - 1
    if start is not None:
        start_h = int(_ts(start) // 3600)
    elif days:
        start_h = end_h - days * 24 + 1
    else:
        start_h = first_h
    start_h = max(start_h, first_h)

    count = [[0] * 24 for _ in range(7)]
    nbytes = [[0] * 24 for _ in range(7)]
    slots = [[0] * 24 for _ in range(7)]
    for h in range(start_h, end_h + 1):
        lt = datetime.fromtimestamp(h * 3600, zone)
        d, hr = lt.weekday(), lt.hour
        slots[d][hr] += 1
        v = series.get(h)
        if v:
            count[d][hr] += v[0]
            nbytes[d][hr] += v[1]

    def _iso(h: int) -> str:
        return datetime.fromtimestamp(h * 3600, timezone.utc).isoformat()

    return {
        "source": source, "kind": kind, "tz": tz_name,
        "start": _iso(start_h) if end_h >= start_h else None,
        "end": _iso(end_h + 1) if end_h >= start_h else None,
        "first_data": _iso(first_h) if series else None,
        "count": count, "bytes": nbytes, "slots": slots,
        "total": sum(map(sum, count)), "total_bytes": sum(map(sum, nbytes)),
    }


# ── R/W activity log (trusted + private FTP users) ────────────────────────────
# Rows are written by the logtailer (ftp_activity) for the usernames the backend
# publishes into ftp_activity_users on every sync(). Kept indefinitely — the
# retention pruner only touches the download tables.

ACTIVITY_ACTIONS = ("upload", "download", "delete", "mkdir", "rmdir", "rename", "chmod", "login")


def set_activity_users(users: list[tuple[str, str]]) -> None:
    """Replace the tracked-user list: [(username, 'trusted'|'private'), ...]."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ftp_activity_users (
                    username   TEXT PRIMARY KEY,
                    user_class TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )""")
            cur.execute("DELETE FROM ftp_activity_users")
            if users:
                psycopg2.extras.execute_values(
                    cur, "INSERT INTO ftp_activity_users (username, user_class) VALUES %s", users)
        conn.commit()


def _activity_where(username=None, user_class=None, action=None, ip=None, path=None,
                    result=None, date_from=None, date_to=None) -> tuple[str, list]:
    clauses, params = [], []
    if username:
        clauses.append("username = %s"); params.append(username)
    if user_class in ("trusted", "private"):
        clauses.append("user_class = %s"); params.append(user_class)
    if action:
        acts = [a for a in action.split(",") if a in ACTIVITY_ACTIONS]
        if acts:
            clauses.append("action = ANY(%s)"); params.append(acts)
    if ip:
        clauses.append("HOST(ip_address) ILIKE %s"); params.append(f"%{ip}%")
    if path:
        clauses.append("(path ILIKE %s OR path_from ILIKE %s)"); params += [f"%{path}%", f"%{path}%"]
    if result == "ok":
        clauses.append("success")
    elif result == "fail":
        clauses.append("NOT success")
    if date_from:
        clauses.append("logged_at >= %s"); params.append(date_from)
    if date_to:
        clauses.append("logged_at <= %s"); params.append(date_to)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def get_activity(page: int = 1, limit: int = 100, **filters) -> dict:
    where, params = _activity_where(**filters)
    with _conn() as conn:
        total = _q1(conn, f"SELECT COUNT(*) AS n FROM ftp_activity{where}", params)["n"]
        rows = _q(conn, f"""
            SELECT id, logged_at, HOST(ip_address) AS ip_address, username, user_class, action,
                   command, path, path_from, status, success, bytes
            FROM ftp_activity{where}
            ORDER BY logged_at DESC, id DESC LIMIT %s OFFSET %s""",
            params + [limit, (page - 1) * limit])
    return {"total": total, "page": page, "limit": limit, "rows": [_ser(r) for r in rows]}


def get_activity_summary(days: int = 30, user_class: Optional[str] = None) -> list:
    where, params = _activity_where(user_class=user_class)
    where += (" AND " if where else " WHERE ") + "logged_at >= NOW() - (%s * INTERVAL '1 day')"
    params.append(days)
    sums = ", ".join(f"COUNT(*) FILTER (WHERE action='{a}' AND success) AS {a}" for a in ACTIVITY_ACTIONS)
    with _conn() as conn:
        rows = _q(conn, f"""
            SELECT username, MAX(user_class) AS user_class, {sums},
                   COUNT(*) FILTER (WHERE NOT success) AS failed,
                   COALESCE(SUM(bytes) FILTER (WHERE action='upload' AND success), 0) AS bytes_up,
                   COALESCE(SUM(bytes) FILTER (WHERE action='download' AND success), 0) AS bytes_down,
                   MAX(logged_at) AS last_seen, COUNT(DISTINCT HOST(ip_address)) AS ips
            FROM ftp_activity{where}
            GROUP BY username ORDER BY MAX(logged_at) DESC""", params)
    return [_json_safe(_ser(r)) for r in rows]


def export_activity_csv(**filters) -> str:
    where, params = _activity_where(**filters)
    with _conn() as conn:
        rows = _q(conn, f"""
            SELECT logged_at AT TIME ZONE 'UTC' AS logged_at, HOST(ip_address) AS ip_address,
                   username, user_class, action, command, path, path_from, status, success, bytes
            FROM ftp_activity{where} ORDER BY logged_at DESC, id DESC LIMIT 500000""", params)
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["logged_at", "ip_address", "username", "user_class", "action", "command",
            "path", "path_from", "status", "success", "bytes"]
    w.writerow(["timestamp_utc"] + cols[1:])
    for r in rows:
        w.writerow([r[c] for c in cols])
    return buf.getvalue()


def get_activity_backfill_status() -> dict:
    return {"done": (get_tailer_config("activity_backfill_done") or "false") == "true",
            "progress": get_tailer_config("activity_backfill_progress") or "0%"}
