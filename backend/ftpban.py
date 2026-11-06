"""
Portal side of the FTP ban system (anonymous idle / reconnect abuse).

Detection and enforcement run on the host in ciosuseradd-ftpban
(ftpban/ftpban.py), which owns the SQLite schema and default settings. This
module only reads that DB (bind-mounted at settings.ftpban_db_path) and writes
the three things the daemon picks up within ~2s: manual bans, unbans/expiry
changes, and the settings row (which also holds the whitelist).
"""
import ipaddress
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Optional

from config import settings

EVENTS = ("notransfer", "idle", "connect", "aborted")
HEARTBEAT_STALE_S = 15


class FtpBanUnavailable(Exception):
    pass


@contextmanager
def _conn():
    if not os.path.exists(settings.ftpban_db_path):
        raise FtpBanUnavailable("No ban database found — is the ciosuseradd-ftpban service running on the FTP host?")
    db = sqlite3.connect(settings.ftpban_db_path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=10000")
    try:
        yield db
    finally:
        db.close()


def _status(db, key):
    r = db.execute("SELECT value FROM status WHERE key=?", (key,)).fetchone()
    return r["value"] if r else None


def norm_ip(ip: str) -> str:
    try:
        return ipaddress.ip_address(ip.strip()).compressed
    except ValueError:
        raise ValueError("Not a valid IPv4/IPv6 address")


def _ban_row(r) -> dict:
    d = dict(r)
    d["dry_run"] = bool(d["dry_run"])
    d["active"] = d["lifted_at"] is None
    return d


# ── status ───────────────────────────────────────────────────────────────────

def get_status() -> dict:
    with _conn() as db:
        now = int(time.time())
        hb = int(_status(db, "heartbeat") or 0)
        fw = json.loads(_status(db, "firewall") or "{}")
        s = json.loads(db.execute("SELECT json FROM settings WHERE id=1").fetchone()["json"])
        q = lambda sql, *a: db.execute(sql, a).fetchone()[0]
        try:
            wd = json.loads(_status(db, "watchdog") or "null")
        except ValueError:
            wd = None
        return {
            "watchdog":        wd,   # {state: ok|failopen|disabled, reason, checked_at, ...} or None
            "daemon_ok":       now - hb <= HEARTBEAT_STALE_S,
            "heartbeat_age_s": now - hb if hb else None,
            "firewall":        fw,
            "last_error":      _status(db, "last_error"),
            "enforce":         bool(s.get("enforce", True)),
            "active":          q("SELECT COUNT(*) FROM bans WHERE lifted_at IS NULL AND dry_run=0"),
            "active_auto":     q("SELECT COUNT(*) FROM bans WHERE lifted_at IS NULL AND dry_run=0 AND source='auto'"),
            "active_manual":   q("SELECT COUNT(*) FROM bans WHERE lifted_at IS NULL AND dry_run=0 AND source='manual'"),
            "active_dry_run":  q("SELECT COUNT(*) FROM bans WHERE lifted_at IS NULL AND dry_run=1"),
            "bans_24h":        q("SELECT COUNT(*) FROM bans WHERE dry_run=0 AND created_at>=?", now - 86400),
            "bans_7d":         q("SELECT COUNT(*) FROM bans WHERE dry_run=0 AND created_at>=?", now - 7 * 86400),
            "blocked_packets": q("SELECT COALESCE(SUM(blocked_packets),0) FROM bans WHERE lifted_at IS NULL"),
            "offender_ips_24h": q("SELECT COUNT(DISTINCT ip) FROM offenses WHERE hour>=?", (now - 86400) // 3600),
        }


def _stored_settings(db) -> dict:
    return json.loads(db.execute("SELECT json FROM settings WHERE id=1").fetchone()["json"])


def _wl_nets(db) -> list:
    nets = []
    for item in _stored_settings(db).get("whitelist") or []:
        try:
            nets.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            pass
    return nets


def _in_nets(ip: str, nets: list) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in nets)


def get_watchlist() -> list:
    with _conn() as db:
        wl = json.loads(_status(db, "watchlist") or "[]")
        active = {r["ip"] for r in db.execute("SELECT ip FROM bans WHERE lifted_at IS NULL AND dry_run=0")}
        nets = _wl_nets(db)
    for e in wl:
        e["banned"] = e["ip"] in active
        e["whitelisted"] = _in_nets(e["ip"], nets)
    return wl


# ── bans ─────────────────────────────────────────────────────────────────────

def list_bans(state: str = "active", ip: Optional[str] = None, source: Optional[str] = None,
              limit: int = 100, offset: int = 0) -> dict:
    where, args = [], []
    if state == "active":
        where.append("lifted_at IS NULL")
    elif state == "history":
        where.append("lifted_at IS NOT NULL")
    if ip:
        where.append("ip LIKE ?")
        args.append(f"%{ip.strip()}%")
    if source == "dry_run":
        where.append("dry_run=1")
    elif source in ("auto", "manual"):
        where.append("source=? AND dry_run=0")
        args.append(source)
    w = (" WHERE " + " AND ".join(where)) if where else ""
    with _conn() as db:
        total = db.execute(f"SELECT COUNT(*) FROM bans{w}", args).fetchone()[0]
        rows = db.execute(f"SELECT * FROM bans{w} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                          args + [limit, offset]).fetchall()
    return {"total": total, "bans": [_ban_row(r) for r in rows], "now": int(time.time())}


def manual_ban(ip: str, minutes: Optional[int], reason: Optional[str], by: str) -> dict:
    ip = norm_ip(ip)
    now = int(time.time())
    with _conn() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("UPDATE bans SET lifted_at=?, lifted_by='replaced' WHERE ip=? AND lifted_at IS NULL", (now, ip))
        cur = db.execute(
            "INSERT INTO bans (ip, source, reason, created_at, created_by, expires_at) VALUES (?, 'manual', ?, ?, ?, ?)",
            (ip, (reason or "").strip()[:300] or None, now, by, now + minutes * 60 if minutes else None))
        db.execute("COMMIT")
        return _ban_row(db.execute("SELECT * FROM bans WHERE id=?", (cur.lastrowid,)).fetchone())


def unban(ban_id: int, by: str) -> Optional[dict]:
    with _conn() as db:
        r = db.execute("SELECT * FROM bans WHERE id=? AND lifted_at IS NULL", (ban_id,)).fetchone()
        if not r:
            return None
        db.execute("UPDATE bans SET lifted_at=?, lifted_by=? WHERE id=?", (int(time.time()), f"admin:{by}", ban_id))
        return _ban_row(r)


def unban_ip(ip: str, by: str) -> int:
    ip = norm_ip(ip)
    with _conn() as db:
        return db.execute("UPDATE bans SET lifted_at=?, lifted_by=? WHERE ip=? AND lifted_at IS NULL",
                          (int(time.time()), f"admin:{by}", ip)).rowcount


def set_expiry(ban_id: int, minutes: Optional[int], enforce: Optional[bool] = None) -> Optional[dict]:
    """New expiry counted from now (None = permanent). enforce=True turns a dry-run
    entry into a real ban."""
    now = int(time.time())
    with _conn() as db:
        r = db.execute("SELECT * FROM bans WHERE id=? AND lifted_at IS NULL", (ban_id,)).fetchone()
        if not r:
            return None
        db.execute("UPDATE bans SET expires_at=?, dry_run=CASE WHEN ? THEN 0 ELSE dry_run END WHERE id=?",
                   (now + minutes * 60 if minutes else None, 1 if enforce else 0, ban_id))
        return _ban_row(db.execute("SELECT * FROM bans WHERE id=?", (ban_id,)).fetchone())


# ── stats ────────────────────────────────────────────────────────────────────

def _event_sums(prefix="") -> str:
    return ", ".join(f"SUM(CASE WHEN {prefix}event='{e}' THEN {prefix}count ELSE 0 END) AS {e}" for e in EVENTS)


def top_offenders(days: int = 7, sort: str = "total", limit: int = 50) -> list:
    since_h = (int(time.time()) - days * 86400) // 3600
    order = sort if sort in EVENTS + ("bans",) else "total"
    with _conn() as db:
        rows = db.execute(f"""
            WITH o AS (
                SELECT ip, {_event_sums()}, SUM(count) AS total, MAX(hour) AS last_hour
                FROM offenses WHERE hour >= ? GROUP BY ip
            ), b AS (
                SELECT ip, COUNT(*) AS bans, MAX(lifted_at IS NULL) AS banned
                FROM bans WHERE dry_run=0 AND created_at >= ? GROUP BY ip
            )
            SELECT o.*, COALESCE(b.bans, 0) AS bans,
                   EXISTS (SELECT 1 FROM bans x WHERE x.ip=o.ip AND x.lifted_at IS NULL AND x.dry_run=0) AS banned
            FROM o LEFT JOIN b ON b.ip = o.ip
            ORDER BY {order} DESC, total DESC LIMIT ?""",
            (since_h, since_h * 3600, limit)).fetchall()
        nets = _wl_nets(db)
    out = []
    for r in rows:
        d = dict(r)
        d["banned"] = bool(d["banned"])
        d["whitelisted"] = _in_nets(d["ip"], nets)
        d["last_seen"] = d.pop("last_hour") * 3600
        out.append(d)
    return out


def timeline(days: int = 30) -> dict:
    now = int(time.time())
    since = now - days * 86400
    with _conn() as db:
        ev = db.execute(f"""
            SELECT (hour * 3600) / 86400 AS day, {_event_sums()}
            FROM offenses WHERE hour >= ? GROUP BY day ORDER BY day""", (since // 3600,)).fetchall()
        bans = db.execute("""
            SELECT created_at / 86400 AS day,
                   SUM(CASE WHEN dry_run=0 AND source='auto' THEN 1 ELSE 0 END) AS auto,
                   SUM(CASE WHEN dry_run=0 AND source='manual' THEN 1 ELSE 0 END) AS manual,
                   SUM(dry_run) AS dry_run
            FROM bans WHERE created_at >= ? GROUP BY day ORDER BY day""", (since,)).fetchall()
    return {"events": [dict(r) | {"day": r["day"] * 86400} for r in ev],
            "bans": [dict(r) | {"day": r["day"] * 86400} for r in bans]}


def ip_detail(ip: str) -> dict:
    ip = norm_ip(ip)
    since_h = (int(time.time()) - 30 * 86400) // 3600
    with _conn() as db:
        bans = db.execute("SELECT * FROM bans WHERE ip=? ORDER BY created_at DESC LIMIT 100", (ip,)).fetchall()
        days = db.execute(f"""
            SELECT (hour * 3600) / 86400 AS day, {_event_sums()}
            FROM offenses WHERE ip=? AND hour >= ? GROUP BY day ORDER BY day""", (ip, since_h)).fetchall()
        whitelisted = _in_nets(ip, _wl_nets(db))
    return {"ip": ip, "whitelisted": whitelisted, "bans": [_ban_row(r) for r in bans],
            "days": [dict(r) | {"day": r["day"] * 86400} for r in days]}


def request_watchdog_retry() -> None:
    """Ask the host watchdog to try recovering from fail-open on its next run (≤30s)."""
    with _conn() as db:
        db.execute("INSERT INTO status (key, value) VALUES ('watchdog_retry', ?) "
                   "ON CONFLICT (key) DO UPDATE SET value=excluded.value", (str(int(time.time())),))


# ── settings ─────────────────────────────────────────────────────────────────

def get_settings() -> dict:
    with _conn() as db:
        r = db.execute("SELECT json, updated_at, updated_by FROM settings WHERE id=1").fetchone()
    return {"settings": json.loads(r["json"]), "updated_at": r["updated_at"], "updated_by": r["updated_by"]}


def _write_settings(db, s: dict, by: str) -> None:
    # The daemon reloads when updated_at changes, so it must never repeat.
    prev = db.execute("SELECT updated_at FROM settings WHERE id=1").fetchone()[0]
    db.execute("UPDATE settings SET json=?, updated_at=?, updated_by=? WHERE id=1",
               (json.dumps(s), max(int(time.time()), prev + 1), by))




def save_settings(new: dict, by: str) -> None:
    """Save the Settings form. The whitelist is edited separately (see below), so the
    stored whitelist is kept rather than overwritten by whatever the form had loaded."""
    with _conn() as db:
        db.execute("BEGIN IMMEDIATE")
        cur = _stored_settings(db)
        new["whitelist"] = cur.get("whitelist") or []
        new["whitelist_meta"] = cur.get("whitelist_meta") or {}
        _write_settings(db, new, by)
        db.execute("COMMIT")


# ── whitelist ────────────────────────────────────────────────────────────────
# Stored in the settings row: `whitelist` (list of IP/CIDR strings — the only part
# the daemon needs) plus `whitelist_meta` ({entry: {note, by, at}}) for the portal.

def _canon(entry: str) -> Optional[str]:
    try:
        net = ipaddress.ip_network(str(entry).strip(), strict=False)
    except ValueError:
        return None
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else net.compressed


def get_whitelist() -> list:
    with _conn() as db:
        s = _stored_settings(db)
    meta = s.get("whitelist_meta") or {}
    out = []
    for item in s.get("whitelist") or []:
        m = meta.get(item) or {}
        out.append({"entry": item, "canonical": _canon(item), "note": m.get("note"),
                    "created_by": m.get("by"), "created_at": m.get("at")})
    return out


def add_whitelist(entry: str, note: Optional[str], by: str) -> dict:
    """Add an IP/CIDR. Active auto bans (and dry-run entries) it covers are lifted
    right away — the daemon only consults the whitelist before creating a ban."""
    net = ipaddress.ip_network(entry, strict=False)
    now = int(time.time())
    with _conn() as db:
        db.execute("BEGIN IMMEDIATE")
        s = _stored_settings(db)
        wl = s.get("whitelist") or []
        if any(_canon(x) == entry for x in wl):
            db.execute("ROLLBACK")
            raise ValueError(f"{entry} is already whitelisted")
        if len(wl) >= 500:
            db.execute("ROLLBACK")
            raise ValueError("Whitelist is full (500 entries)")
        s["whitelist"] = wl + [entry]
        s.setdefault("whitelist_meta", {})[entry] = {"note": (note or "").strip()[:300] or None, "by": by, "at": now}
        _write_settings(db, s, by)
        lifted = []
        for r in db.execute("SELECT id, ip FROM bans WHERE lifted_at IS NULL AND source='auto'").fetchall():
            a = ipaddress.ip_address(r["ip"])
            if a.version == net.version and a in net:
                lifted.append(r["id"])
        for i in lifted:
            db.execute("UPDATE bans SET lifted_at=?, lifted_by='whitelisted' WHERE id=?", (now, i))
        db.execute("COMMIT")
    return {"entry": entry, "lifted": len(lifted)}


def remove_whitelist(entry: str, by: str) -> bool:
    canon = _canon(entry)
    with _conn() as db:
        db.execute("BEGIN IMMEDIATE")
        s = _stored_settings(db)
        wl = s.get("whitelist") or []
        keep = [x for x in wl if x != entry and (canon is None or _canon(x) != canon)]
        if len(keep) == len(wl):
            db.execute("ROLLBACK")
            return False
        meta = s.get("whitelist_meta") or {}
        s["whitelist"] = keep
        s["whitelist_meta"] = {k: v for k, v in meta.items() if k in keep}
        _write_settings(db, s, by)
        db.execute("COMMIT")
    return True
