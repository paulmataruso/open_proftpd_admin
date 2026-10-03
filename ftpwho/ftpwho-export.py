#!/usr/bin/env python3
"""Host-side ftpwho exporter for ciosuseradd.

ProFTPd runs on the host, not in the compose stack, and its scoreboard is only
readable with the host's own `ftpwho` binary. This loop snapshots
`ftpwho -v -o json` every FTPWHO_INTERVAL seconds and writes it atomically to
FTPWHO_DIR/ftpwho.json, which is bind-mounted read-only into the backend
(served at GET /admin/ftpwho for the "Live Sessions" admin panel).

Install: see ftpwho/ciosuseradd-ftpwho.service.
"""
import json
import os
import subprocess
import sys
import time

OUT_DIR  = os.environ.get("FTPWHO_DIR", "/var/lib/ciosuseradd/ftpwho")
INTERVAL = float(os.environ.get("FTPWHO_INTERVAL", "1"))
FTPWHO   = os.environ.get("FTPWHO_BIN", "ftpwho")
OUT_PATH = os.path.join(OUT_DIR, "ftpwho.json")


def snapshot() -> dict:
    snap = {"generated_ms": int(time.time() * 1000), "ok": False, "error": None,
            "server": None, "connections": []}
    try:
        proc = subprocess.run([FTPWHO, "-v", "-o", "json"], capture_output=True,
                              timeout=10, text=True, errors="replace")
        # ftpwho prints a "no connections" style message (not JSON) when idle.
        out = proc.stdout.strip()
        if not out.startswith("{"):
            snap["ok"] = proc.returncode == 0
            snap["error"] = None if snap["ok"] else (proc.stderr.strip() or out or f"exit {proc.returncode}")
            return snap
        data = json.loads(out, strict=False)
        snap["ok"] = True
        snap["server"] = data.get("server")
        snap["connections"] = data.get("connections") or []
    except Exception as e:
        snap["error"] = f"{type(e).__name__}: {e}"
    return snap


def write_atomic(snap: dict):
    tmp = OUT_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(snap, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUT_PATH)


def main():
    os.makedirs(OUT_DIR, mode=0o755, exist_ok=True)
    while True:
        started = time.monotonic()
        try:
            write_atomic(snapshot())
        except Exception as e:
            print(f"ftpwho-export: write failed: {e}", file=sys.stderr, flush=True)
        time.sleep(max(0.0, INTERVAL - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
