#!/usr/bin/env python3
"""Watchdog + fail-open guardrail for ciosuseradd-ftpban.

Run every 30s by ciosuseradd-ftpban-watchdog.timer (oneshot — nothing
long-lived that could itself hang). Each run:

  healthy    = unit active, DB heartbeat fresh, nftables sync OK, and a real
               probe of the ban-message responder (loopback) answers "421".
  unhealthy  -> restart the ban daemon, wait for it to come back healthy.
  restart fails on FAIL_AFTER consecutive runs
             -> FAIL OPEN: stop the daemon and delete its nftables table, so
                no IP is blocked or redirected and FTP works for everyone.
  failed open -> retry every RETRY_EVERY seconds, or immediately when the
                portal requests it (status key watchdog_retry).

If the daemon unit is disabled (taken out of service on purpose), the watchdog
doesn't restart it — it only makes sure the table is gone (fail open).

State lives in FTPBAN_DIR/watchdog.json and is mirrored into the DB status
table (key "watchdog") for the FTP Bans panel.
"""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time

DATA_DIR    = os.environ.get("FTPBAN_DIR", "/var/lib/ciosuseradd/ftpban")
DB_PATH     = os.path.join(DATA_DIR, "ftpban.db")
STATE_PATH  = os.path.join(DATA_DIR, "watchdog.json")
UNIT        = "ciosuseradd-ftpban.service"
NFT         = os.environ.get("NFT_BIN", "/usr/sbin/nft")
NFT_TABLE   = "ciosuseradd_ftpban"

HEARTBEAT_MAX = 20    # seconds
RECOVER_WAIT  = 25    # seconds to wait for health after a (re)start
FAIL_AFTER    = 2     # consecutive failed restarts before failing open
RETRY_EVERY   = 600   # seconds between recovery attempts while failed open


def log(msg):
    print(msg, flush=True)


def sh(*args, timeout=30):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)


def db():
    c = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)
    c.execute("PRAGMA busy_timeout=5000")
    return c


def get_status(key):
    try:
        with db() as c:
            r = c.execute("SELECT value FROM status WHERE key=?", (key,)).fetchone()
            return r[0] if r else None
    except Exception:
        return None


def set_status(key, value):
    try:
        c = db()
        c.execute("INSERT INTO status (key, value) VALUES (?, ?) "
                  "ON CONFLICT (key) DO UPDATE SET value=excluded.value", (key, value))
        c.close()
    except Exception as e:
        log(f"could not write status to DB: {e}")


def responder_port():
    try:
        with db() as c:
            s = json.loads(c.execute("SELECT json FROM settings WHERE id=1").fetchone()[0])
        return int(s.get("responder_port") or 10021)
    except Exception:
        return 10021


def health():
    """(ok, reason)"""
    if sh("systemctl", "is-active", "--quiet", UNIT).returncode != 0:
        return False, "ban daemon is not running"
    hb = get_status("heartbeat")
    if not hb:
        return False, "no heartbeat in DB"
    age = time.time() - int(hb)
    if age > HEARTBEAT_MAX:
        return False, f"heartbeat {int(age)}s old (daemon hung?)"
    try:
        fw = json.loads(get_status("firewall") or "{}")
    except ValueError:
        fw = {}
    if fw.get("ok") is False:
        return False, f"nftables sync failing: {fw.get('error')}"
    port = responder_port()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.settimeout(3)
            line = s.recv(512).decode("utf-8", "replace")
        if not line.startswith("421"):
            return False, f"responder on {port} answered {line[:40]!r}"
    except OSError as e:
        return False, f"responder on {port} not answering: {e}"
    return True, "healthy"


def table_exists():
    return sh(NFT, "list", "table", "inet", NFT_TABLE).returncode == 0


def fail_open(reason):
    sh("systemctl", "stop", UNIT)
    if table_exists():
        r = sh(NFT, "delete", "table", "inet", NFT_TABLE)
        if r.returncode != 0:
            log(f"!! could not delete nft table: {r.stderr.strip()}")
    log(f"FAIL OPEN: {reason} — ban daemon stopped, nftables table removed, nothing is blocked")


def try_recover():
    """Restart the daemon and wait for health. Returns (ok, reason)."""
    sh("systemctl", "reset-failed", UNIT)
    sh("systemctl", "restart", UNIT, timeout=60)
    deadline = time.time() + RECOVER_WAIT
    ok, why = False, "not checked"
    while time.time() < deadline:
        time.sleep(3)
        ok, why = health()
        if ok:
            break
    return ok, why


def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(st):
    st["checked_at"] = int(time.time())
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_PATH)
    set_status("watchdog", json.dumps(st))


def main():
    st = load_state()
    st.setdefault("state", "ok")          # ok | failopen | disabled
    st.setdefault("failures", 0)
    now = int(time.time())

    if sh("systemctl", "is-enabled", "--quiet", UNIT).returncode != 0:
        if table_exists():
            fail_open("ban daemon unit is disabled")
        st.update(state="disabled", reason="ban daemon unit is disabled — bans not enforced", failures=0)
        save_state(st)
        return

    retry_req = get_status("watchdog_retry")
    retry_now = bool(retry_req and int(retry_req) > st.get("last_attempt", 0))

    if st["state"] == "failopen":
        if not retry_now and now - st.get("last_attempt", 0) < RETRY_EVERY:
            if sh("systemctl", "is-active", "--quiet", UNIT).returncode == 0:
                ok, why = health()            # started by hand while waiting?
                if ok:
                    log("daemon was started manually and is healthy — leaving fail-open")
                    st.update(state="ok", reason="recovered (manual start)", failures=0, recovered_at=now)
                else:
                    fail_open(f"manual start unhealthy: {why}")
            elif table_exists():
                fail_open("stale table while failed open")
            save_state(st)
            return
        log("failed open — attempting recovery" + (" (requested from portal)" if retry_now else ""))
        st["last_attempt"] = now
        ok, why = try_recover()
        if ok:
            log("recovered — ban enforcement is back on")
            st.update(state="ok", reason="recovered", failures=0, recovered_at=int(time.time()))
        else:
            st["reason"] = why
            fail_open(why)
        save_state(st)
        return

    ok, why = health()
    if ok:
        st.update(state="ok", reason="healthy", failures=0)
        save_state(st)
        return

    log(f"unhealthy: {why} — restarting {UNIT}")
    st["last_attempt"] = now
    ok, why2 = try_recover()
    if ok:
        log("restart fixed it")
        st.update(state="ok", reason=f"auto-restarted after: {why}", failures=0, last_restart=now)
    else:
        st["failures"] = st.get("failures", 0) + 1
        st["reason"] = why2
        log(f"restart did not help ({why2}); consecutive failures: {st['failures']}/{FAIL_AFTER}")
        if st["failures"] >= FAIL_AFTER:
            fail_open(why2)
            st.update(state="failopen", failopen_since=now)
    save_state(st)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Last-ditch guardrail: never leave a stale ban table behind a crashed watchdog.
        log(f"watchdog error: {e!r}")
        try:
            if sh("systemctl", "is-active", "--quiet", UNIT).returncode != 0 and table_exists():
                fail_open(f"watchdog error with daemon down: {e!r}")
        except Exception:
            pass
        sys.exit(1)
