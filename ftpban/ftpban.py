#!/usr/bin/env python3
"""Host-side FTP ban detector + nftables enforcer for ciosuseradd.

Detects anonymous FTP abuse (idle squatting, reconnect storms, abort loops) and
temporarily blocks the offending IPs.

Why not ProFTPd's mod_ban: BanOnEvent is server-wide (it can't be limited to
anonymous users — ClientConnectRate fires before login), `ftpdctl ban` bans
never expire, and on this ProFTPd build (1.3.8b) a config reload with mod_ban
enabled segfaults the master — while this stack depends on reloads for new
trusted/private users. So enforcement is a dedicated nftables table instead:
instant, no ProFTPd reload ever, and it also cuts a banned IP's open sessions.

  * ProFTPd writes a dedicated session log (proftpd/ftpd_ban.conf): one line per
    AUTH/READ command and per session end: epoch|pid|ip|user|cmd|status|reason.
  * This loop counts events for ANONYMOUS sessions only (settings.anon_users),
    applies the rules from the `settings` row and records bans in SQLite
    (FTPBAN_DIR/ftpban.db).
  * Every RECONCILE_EVERY seconds it syncs the nftables sets with the active
    bans in the DB and expires bans. New connections from a banned IP to the
    FTP control port are redirected to a tiny built-in responder (responder_port)
    that replies "421 <ban message for that ban type>" and hangs up, so clients
    see why; everything else from a banned IP on the FTP ports (passive data,
    already-open sessions) gets a TCP reset.

The DB is the interface to the portal: the backend bind-mounts FTPBAN_DIR,
reads bans/stats/status from it, and writes manual bans, unbans and settings
into it; this loop applies them within RECONCILE_EVERY seconds. The schema
and default settings are owned here.

Install: see ftpban/ciosuseradd-ftpban.service.
"""
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque

DATA_DIR    = os.environ.get("FTPBAN_DIR", "/var/lib/ciosuseradd/ftpban")
DB_PATH     = os.path.join(DATA_DIR, "ftpban.db")
SESSION_LOG = os.environ.get("FTPBAN_SESSION_LOG", "/var/log/proftpd-ciosban/session.log")
NFT         = os.environ.get("NFT_BIN", "/usr/sbin/nft")
NFT_TABLE   = "ciosuseradd_ftpban"   # inet family; owned entirely by this daemon

LOOP_SECONDS    = 1.0
RECONCILE_EVERY = 2      # seconds
FLUSH_EVERY     = 10     # seconds — hourly offense counters
PRUNE_EVERY     = 3600   # seconds
WATCHLIST_SIZE  = 50

EVENTS = ("notransfer", "idle", "connect", "aborted")
PORTS_RE = re.compile(r"^\s*\d{1,5}(\s*-\s*\d{1,5})?(\s*,\s*\d{1,5}(\s*-\s*\d{1,5})?)*\s*$")

DEFAULT_SETTINGS = {
    "enforce": True,  # False = dry run: auto bans are recorded but not enforced
    "anon_users": ["anonftp"],
    "rules": {
        "notransfer": {"enabled": True,  "count": 5,  "window_min": 30, "ban_min": 60},
        "idle":       {"enabled": True,  "count": 5,  "window_min": 30, "ban_min": 60},
        "connect":    {"enabled": True,  "count": 30, "window_min": 10, "ban_min": 60},
        "aborted":    {"enabled": False, "count": 50, "window_min": 10, "ban_min": 60},
    },
    "escalation": {"enabled": False, "multiplier": 2, "lookback_days": 7, "max_ban_hours": 168},
    "whitelist": ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "whitelist_meta": {},        # portal-only: {entry: {note, by, at}}
    "ports": "21,15000-30000",   # everything blocked for a banned IP (control + PassivePorts)
    "control_port": 21,          # new connections here get the ban message instead of a reset
    "responder_port": 10021,     # local port of the ban-message responder (redirect target)
    "retention_days": 90,
    # 421 reply per ban type. Placeholders: {remaining} {expires} {ip} {reason}
    "messages": {
        "notransfer": "Temporarily banned: too many anonymous sessions that connected but never downloaded. Try again in {remaining}.",
        "idle":       "Temporarily banned: too many idle anonymous sessions. Try again in {remaining}.",
        "connect":    "Temporarily banned: too many connections in a short time. Try again in {remaining}.",
        "aborted":    "Temporarily banned: too many aborted transfers. Try again in {remaining}.",
        "manual":     "Your IP ({ip}) has been banned from this FTP server. Ban ends: {expires}.",
    },
}
MESSAGE_TYPES = ("notransfer", "idle", "connect", "aborted", "manual")

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    json       TEXT    NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT
);
CREATE TABLE IF NOT EXISTS bans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL,
    source     TEXT    NOT NULL,            -- auto | manual
    rule       TEXT,                        -- event that triggered an auto ban
    reason     TEXT,
    created_at INTEGER NOT NULL,
    created_by TEXT,
    expires_at INTEGER,                     -- NULL = permanent
    lifted_at  INTEGER,                     -- NULL = active
    lifted_by  TEXT,                        -- expired | replaced | admin:<name>
    dry_run    INTEGER NOT NULL DEFAULT 0,  -- 1 = "would have banned" (not enforced)
    blocked_packets INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS bans_active  ON bans (lifted_at, ip);
CREATE INDEX IF NOT EXISTS bans_created ON bans (created_at);
CREATE TABLE IF NOT EXISTS offenses (
    ip    TEXT    NOT NULL,
    hour  INTEGER NOT NULL,                 -- epoch // 3600
    event TEXT    NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (ip, hour, event)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS offenses_hour ON offenses (hour);
CREATE TABLE IF NOT EXISTS status (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

log = logging.getLogger("ftpban")


# ── helpers ──────────────────────────────────────────────────────────────────

def norm_ip(ip: str):
    try:
        return ipaddress.ip_address(ip.strip()).compressed
    except ValueError:
        return None


def merged_settings(raw: dict) -> dict:
    s = json.loads(json.dumps(DEFAULT_SETTINGS))
    for k, v in (raw or {}).items():
        if k == "rules" and isinstance(v, dict):
            for ev, r in v.items():
                if ev in s["rules"] and isinstance(r, dict):
                    s["rules"][ev].update(r)
        elif k in ("escalation", "messages") and isinstance(v, dict):
            s[k].update({mk: mv for mk, mv in v.items() if mk in s[k]})
        elif k in s:
            s[k] = v
    if not PORTS_RE.match(str(s["ports"])):
        s["ports"] = DEFAULT_SETTINGS["ports"]
    for k in ("control_port", "responder_port"):
        try:
            s[k] = int(s[k]) if 1 <= int(s[k]) <= 65535 else DEFAULT_SETTINGS[k]
        except (TypeError, ValueError):
            s[k] = DEFAULT_SETTINGS[k]
    return s


def _human(seconds: int) -> str:
    m = max(1, round(seconds / 60))
    d, m = divmod(m, 1440)
    h, m = divmod(m, 60)
    parts = [f"{d} day{'s' * (d != 1)}" if d else "", f"{h} hour{'s' * (h != 1)}" if h else "",
             f"{m} minute{'s' * (m != 1)}" if m and not d else ""]
    return " ".join(p for p in parts if p)


def render_message(template: str, ban: dict) -> str:
    """Fill a ban-message template. Output is a single FTP reply line."""
    now = int(time.time())
    exp = ban.get("expires_at")
    vals = {
        "remaining": _human(exp - now) if exp else "never (permanent ban)",
        "expires":   time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(exp)) if exp else "never (permanent ban)",
        "ip":        ban.get("ip") or "",
        "reason":    ban.get("reason") or "",
    }
    out = re.sub(r"\{(remaining|expires|ip|reason)\}", lambda m: vals[m.group(1)], str(template or ""))
    out = re.sub(r"[\x00-\x1f\x7f]", " ", out).strip()
    return out[:400] or "Your IP is banned from this FTP server."


def nft_ports(ports: str) -> str:
    return ", ".join(re.sub(r"\s+", "", p) for p in str(ports).split(","))


# ── daemon ───────────────────────────────────────────────────────────────────

class FtpBan:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.db = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.executescript(SCHEMA)
        os.chmod(DB_PATH, 0o600)
        if not self.db.execute("SELECT 1 FROM settings WHERE id=1").fetchone():
            self.db.execute("INSERT INTO settings (id, json, updated_at, updated_by) VALUES (1, ?, ?, 'default')",
                            (json.dumps(DEFAULT_SETTINGS), int(time.time())))
        self.settings = DEFAULT_SETTINGS
        self.settings_ts = None
        self.whitelist = []
        self.nft_ports = None
        self.windows = defaultdict(deque)       # (event, ip) -> deque[epoch]
        self.pending = defaultdict(int)          # (ip, hour, event) -> count
        self.last_ban_at = {}                    # ip -> epoch of most recent ban
        self.log_fh = None
        self.log_ino = None
        self.log_pos = 0
        self.fw_ok = None
        self.fw_error = None
        self.enforced = set()
        self.ban_messages = {}                   # ip -> rendered 421 text (read by the responder thread)
        self.responder = None
        self.responder_error = None
        self._last_reconcile = self._last_flush = self._last_prune = 0
        self.load_settings(force=True)
        for r in self.db.execute("SELECT ip, MAX(created_at) AS t FROM bans GROUP BY ip"):
            self.last_ban_at[r["ip"]] = r["t"]
        self.open_log(replay=True)

    # settings ────────────────────────────────────────────────────────────────
    def load_settings(self, force=False):
        row = self.db.execute("SELECT json, updated_at FROM settings WHERE id=1").fetchone()
        if not row or (not force and row["updated_at"] == self.settings_ts):
            return
        try:
            raw = json.loads(row["json"])
            self.settings = merged_settings(raw)
        except Exception as e:
            log.error("bad settings json, keeping previous: %s", e)
            return
        self.settings_ts = row["updated_at"]
        if force and self.settings != raw:
            # Persist defaults for keys added since these settings were saved, so
            # the portal (which reads the stored JSON as-is) sees every field.
            self.db.execute("UPDATE settings SET json=? WHERE id=1", (json.dumps(self.settings),))
        wl = []
        for item in self.settings.get("whitelist") or []:
            try:
                wl.append(ipaddress.ip_network(str(item).strip(), strict=False))
            except ValueError:
                log.warning("ignoring bad whitelist entry %r", item)
        self.whitelist = wl
        if not force:
            log.info("settings reloaded (enforce=%s)", self.settings.get("enforce"))

    def whitelisted(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(a.version == n.version and a in n for n in self.whitelist)

    # session log ────────────────────────────────────────────────────────────
    def open_log(self, replay=False):
        """Open the session log. On startup, replay it to rebuild rule windows
        (no stats double-counting: lines before the saved offset only feed
        windows, and only events newer than the IP's last ban count)."""
        try:
            fh = open(SESSION_LOG, "rb")
        except FileNotFoundError:
            self.log_fh = None
            return
        st = os.fstat(fh.fileno())
        saved = {}
        if replay:
            row = self.get_status("log_pos")
            saved = json.loads(row) if row else {}
        self.log_fh, self.log_ino = fh, st.st_ino
        if replay and saved.get("ino") == st.st_ino and saved.get("pos", 0) <= st.st_size:
            stats_from = saved["pos"]
        elif replay:
            stats_from = st.st_size  # unknown file: windows only, no stats
        else:
            stats_from = 0           # rotated/new file: everything is new
        horizon = time.time() - 60 * max(r["window_min"] for r in self.settings["rules"].values())
        while True:
            raw = fh.readline()
            if not raw.endswith(b"\n"):
                fh.seek(fh.tell() - len(raw))  # partial trailing line: read it later
                break
            self.handle_line(raw.decode("utf-8", "replace"), count_stats=fh.tell() > stats_from, min_ts=horizon)
        self.log_pos = fh.tell()

    def poll_log(self):
        try:
            st = os.stat(SESSION_LOG)
        except FileNotFoundError:
            return
        if self.log_fh is None or st.st_ino != self.log_ino:
            if self.log_fh:
                self.drain()           # finish the rotated file first
                self.log_fh.close()
            self.open_log()
            return
        if st.st_size < self.log_pos:  # copytruncate
            self.log_fh.seek(0)
            self.log_pos = 0
        self.drain()

    def drain(self):
        while True:
            raw = self.log_fh.readline()
            if not raw.endswith(b"\n"):
                self.log_fh.seek(self.log_pos)  # nothing new, or a partial line: retry later
                break
            self.log_pos = self.log_fh.tell()
            self.handle_line(raw.decode("utf-8", "replace"))

    @staticmethod
    def classify(cmd: str, status: str, reason: str):
        if cmd == "PASS" and status == "230":
            return "connect"
        if cmd == "EXIT":
            if "TimeoutNoTransfer" in reason:
                return "notransfer"
            if "TimeoutIdle" in reason:
                return "idle"
        if cmd in ("RETR", "STOR", "APPE") and status == "426":
            return "aborted"
        return None

    def handle_line(self, line, count_stats=True, min_ts=0):
        parts = line.rstrip("\n").split("|", 6)
        if len(parts) != 7:
            return
        epoch, _pid, ip, user, cmd, status, reason = parts
        if user not in self.settings["anon_users"]:
            return
        event = self.classify(cmd, status, reason)
        ip = norm_ip(ip)
        if not event or not ip:
            return
        try:
            ts = int(epoch)
        except ValueError:
            return
        if count_stats:
            self.pending[(ip, ts // 3600, event)] += 1
        if ts < min_ts or ts <= self.last_ban_at.get(ip, 0):
            return
        rule = self.settings["rules"].get(event)
        if not rule or not rule.get("enabled"):
            return
        win = self.windows[(event, ip)]
        win.append(ts)
        cutoff = ts - int(rule["window_min"]) * 60
        while win and win[0] <= cutoff:
            win.popleft()
        if len(win) >= int(rule["count"]) and count_stats:
            self.auto_ban(ip, event, rule, len(win), ts)

    # bans ───────────────────────────────────────────────────────────────────
    def active_ban(self, ip):
        # Once enforcing, a leftover dry-run "would ban" mustn't block a real ban.
        include_dry = 0 if self.settings.get("enforce") else 1
        return self.db.execute("SELECT * FROM bans WHERE ip=? AND lifted_at IS NULL AND (dry_run=0 OR ?)",
                               (ip, include_dry)).fetchone()

    def auto_ban(self, ip, event, rule, count, ts):
        if self.whitelisted(ip) or self.active_ban(ip):
            return
        now = int(time.time())
        minutes = int(rule["ban_min"])
        esc = self.settings["escalation"]
        prior = 0
        if esc.get("enabled"):
            prior = self.db.execute(
                "SELECT COUNT(*) FROM bans WHERE ip=? AND source='auto' AND dry_run=0 AND created_at>=?",
                (ip, now - int(esc["lookback_days"]) * 86400)).fetchone()[0]
            minutes = min(minutes * (float(esc["multiplier"]) ** prior), int(esc["max_ban_hours"]) * 60)
        dry = 0 if self.settings.get("enforce") else 1
        reason = f"{count} {event} events in {rule['window_min']} min"
        if prior:
            reason += f" (repeat #{prior + 1})"
        self.db.execute(
            "INSERT INTO bans (ip, source, rule, reason, created_at, created_by, expires_at, dry_run) "
            "VALUES (?, 'auto', ?, ?, ?, 'detector', ?, ?)",
            (ip, event, reason, now, now + int(minutes * 60), dry))
        self.last_ban_at[ip] = max(ts, now)
        for ev in EVENTS:
            self.windows.pop((ev, ip), None)
        log.info("%sban %s for %d min: %s", "DRY-RUN " if dry else "", ip, minutes, reason)

    def expire(self):
        self.db.execute("UPDATE bans SET lifted_at=expires_at, lifted_by='expired' "
                        "WHERE lifted_at IS NULL AND expires_at IS NOT NULL AND expires_at<=?", (int(time.time()),))

    # nftables ───────────────────────────────────────────────────────────────
    def nft(self, *args, stdin=None):
        p = subprocess.run([NFT, *args], input=stdin, capture_output=True, text=True, timeout=30)
        if p.returncode != 0:
            raise RuntimeError((p.stderr or p.stdout).strip()[-300:] or f"nft exit {p.returncode}")
        return p.stdout

    def ensure_table(self):
        """Create (or re-create after reboot / port change) the ban table. Atomic.

        New connections from a banned IP to control_port are DNAT-redirected to the
        responder (which sends the ban message). The responder port only accepts
        redirected traffic and loopback (the watchdog's health probe); other
        direct connections to it are reset. Anything else from a
        banned IP on `ports` (passive data, sessions opened before the ban) is reset.
        """
        ports = nft_ports(self.settings["ports"])
        cport, rport = int(self.settings["control_port"]), int(self.settings["responder_port"])
        sig = (ports, cport, rport)
        exists = subprocess.run([NFT, "list", "table", "inet", NFT_TABLE], capture_output=True).returncode == 0
        if exists and sig == self.nft_ports:
            return
        t = f"inet {NFT_TABLE}"
        self.nft("-f", "-", stdin=f"""
add table {t}
add set {t} banned4 {{ type ipv4_addr; counter; }}
add set {t} banned6 {{ type ipv6_addr; counter; }}
add chain {t} prerouting {{ type nat hook prerouting priority dstnat - 10; policy accept; }}
add chain {t} output {{ type nat hook output priority dstnat - 10; policy accept; }}
add chain {t} input {{ type filter hook input priority filter - 10; policy accept; }}
flush chain {t} prerouting
flush chain {t} output
flush chain {t} input
add rule {t} prerouting tcp dport {cport} ip saddr @banned4 redirect to :{rport}
add rule {t} prerouting tcp dport {cport} ip6 saddr @banned6 redirect to :{rport}
add rule {t} output fib daddr type local tcp dport {cport} ip saddr @banned4 redirect to :{rport}
add rule {t} output fib daddr type local tcp dport {cport} ip6 saddr @banned6 redirect to :{rport}
add rule {t} input tcp dport {rport} ct status dnat accept
add rule {t} input iifname "lo" tcp dport {rport} accept
add rule {t} input tcp dport {rport} reject with tcp reset
add rule {t} input tcp dport {{ {ports} }} ip saddr @banned4 counter reject with tcp reset
add rule {t} input tcp dport {{ {ports} }} ip6 saddr @banned6 counter reject with tcp reset
""")
        self.nft_ports = sig
        log.info("nftables table %s ready (blocked ports %s, control %d -> responder %d)", NFT_TABLE, ports, cport, rport)

    def nft_elements(self) -> dict:
        """ip -> blocked packet count, for both sets."""
        out = {}
        for s in ("banned4", "banned6"):
            data = json.loads(self.nft("-j", "list", "set", "inet", NFT_TABLE, s))
            for item in data.get("nftables", []):
                for e in (item.get("set") or {}).get("elem") or []:
                    if isinstance(e, dict) and "elem" in e:
                        ip = norm_ip(str(e["elem"]["val"]))
                        if ip:
                            out[ip] = int((e["elem"].get("counter") or {}).get("packets", 0))
                    elif isinstance(e, str) and norm_ip(e):
                        out[norm_ip(e)] = 0
        return out

    def reconcile(self):
        self.expire()
        want = {r["ip"] for r in self.db.execute(
            "SELECT DISTINCT ip FROM bans WHERE lifted_at IS NULL AND dry_run=0")}
        try:
            self.ensure_table()
            have = self.nft_elements()
            add, remove = want - set(have), set(have) - want
            for ver, setname in ((4, "banned4"), (6, "banned6")):
                a = sorted(ip for ip in add if ipaddress.ip_address(ip).version == ver)
                r = sorted(ip for ip in remove if ipaddress.ip_address(ip).version == ver)
                for i in range(0, len(a), 200):
                    self.nft("add", "element", "inet", NFT_TABLE, setname, "{ " + ", ".join(a[i:i + 200]) + " }")
                for i in range(0, len(r), 200):
                    self.nft("delete", "element", "inet", NFT_TABLE, setname, "{ " + ", ".join(r[i:i + 200]) + " }")
            if add or remove:
                log.info("nftables sync: +%d -%d", len(add), len(remove))
            # blocked-packet counters onto the active ban rows
            for ip, pkts in have.items():
                if ip in want and pkts:
                    self.db.execute("UPDATE bans SET blocked_packets=? WHERE ip=? AND lifted_at IS NULL AND dry_run=0",
                                    (pkts, ip))
            self.enforced = (set(have) | add) - remove
            self.fw_ok, self.fw_error = True, None
            msgs = self.settings["messages"]
            self.ban_messages = {
                r["ip"]: render_message(msgs.get("manual" if r["source"] == "manual" else (r["rule"] or "manual"),
                                                 msgs["manual"]), dict(r))
                for r in self.db.execute("SELECT * FROM bans WHERE lifted_at IS NULL AND dry_run=0")}
        except Exception as e:
            if self.fw_ok is not False:
                log.error("nftables sync failed: %s", e)
            self.fw_ok, self.fw_error = False, str(e)[:300]

    # ban-message responder ──────────────────────────────────────────────────
    def ensure_responder(self):
        port = int(self.settings["responder_port"])
        if self.responder and self.responder[0] == port and self.responder[1].is_alive():
            return
        if self.responder:
            try:
                self.responder[2].close()
            except OSError:
                pass
        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            srv.bind(("::", port))
            srv.listen(128)
        except OSError as e:
            self.responder, self.responder_error = None, f"responder can't listen on {port}: {e}"
            log.error(self.responder_error)
            return
        th = threading.Thread(target=self._serve, args=(srv,), daemon=True, name="responder")
        th.start()
        self.responder, self.responder_error = (port, th, srv), None
        log.info("ban-message responder listening on [::]:%d", port)

    def _serve(self, srv):
        while True:
            try:
                conn, addr = srv.accept()
            except OSError:
                return  # socket closed (port changed)
            try:
                conn.settimeout(3)
                ip = ipaddress.ip_address(addr[0].split("%")[0])
                ip = (ip.ipv4_mapped or ip).compressed
                msg = self.ban_messages.get(ip, "Service not available, please try again later.")
                conn.sendall(f"421 {msg}\r\n".encode("utf-8", "replace"))
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                conn.close()

    # stats / status ─────────────────────────────────────────────────────────
    def flush(self):
        if not self.pending:
            return
        rows = [(ip, hour, ev, n) for (ip, hour, ev), n in self.pending.items()]
        self.pending.clear()
        self.db.execute("BEGIN")
        self.db.executemany(
            "INSERT INTO offenses (ip, hour, event, count) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (ip, hour, event) DO UPDATE SET count = count + excluded.count", rows)
        self.db.execute("COMMIT")

    def prune(self):
        days = max(1, int(self.settings.get("retention_days") or 90))
        cutoff = int(time.time()) - days * 86400
        self.db.execute("DELETE FROM offenses WHERE hour < ?", (cutoff // 3600,))
        self.db.execute("DELETE FROM bans WHERE lifted_at IS NOT NULL AND lifted_at < ?", (cutoff,))

    def watchlist(self):
        now = time.time()
        by_ip = {}
        for (event, ip), win in list(self.windows.items()):
            rule = self.settings["rules"].get(event)
            if not rule or not rule.get("enabled"):
                self.windows.pop((event, ip), None)
                continue
            cutoff = now - int(rule["window_min"]) * 60
            while win and win[0] <= cutoff:
                win.popleft()
            if not win:
                self.windows.pop((event, ip), None)
                continue
            ratio = len(win) / max(1, int(rule["count"]))
            e = by_ip.setdefault(ip, {"ip": ip, "ratio": 0, "events": []})
            e["events"].append({"event": event, "count": len(win), "threshold": int(rule["count"]),
                                "window_min": int(rule["window_min"])})
            e["ratio"] = max(e["ratio"], ratio)
        return sorted(by_ip.values(), key=lambda e: -e["ratio"])[:WATCHLIST_SIZE]

    def get_status(self, key):
        r = self.db.execute("SELECT value FROM status WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def set_status(self, key, value):
        self.db.execute("INSERT INTO status (key, value) VALUES (?, ?) "
                        "ON CONFLICT (key) DO UPDATE SET value=excluded.value", (key, value))

    def write_status(self):
        self.set_status("heartbeat", str(int(time.time())))
        self.set_status("firewall", json.dumps({
            "ok": self.fw_ok, "error": self.fw_error, "table": f"inet {NFT_TABLE}",
            "ports": self.nft_ports[0] if self.nft_ports else None,
            "control_port": self.settings["control_port"], "responder_port": self.settings["responder_port"],
            "responder_ok": bool(self.responder and self.responder[1].is_alive()),
            "responder_error": self.responder_error, "enforced": sorted(self.enforced)}))
        self.set_status("watchlist", json.dumps(self.watchlist()))
        self.set_status("log_pos", json.dumps({"ino": self.log_ino, "pos": self.log_pos}))

    # main loop ──────────────────────────────────────────────────────────────
    def run(self):
        log.info("started (db=%s, log=%s)", DB_PATH, SESSION_LOG)
        while True:
            try:
                now = time.time()
                self.load_settings()
                self.poll_log()
                if now - self._last_flush >= FLUSH_EVERY:
                    self.flush()
                    self._last_flush = now
                if now - self._last_reconcile >= RECONCILE_EVERY:
                    self.ensure_responder()
                    self.reconcile()
                    self.write_status()
                    self._last_reconcile = now
                if now - self._last_prune >= PRUNE_EVERY:
                    self.prune()
                    self._last_prune = now
            except Exception as e:
                log.exception("loop error: %s", e)
                try:
                    self.set_status("last_error", f"{time.strftime('%F %T')} {e}"[:300])
                except Exception:
                    pass
            time.sleep(LOOP_SECONDS)


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(levelname)s %(message)s")
    FtpBan().run()
