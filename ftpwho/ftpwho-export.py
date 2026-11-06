#!/usr/bin/env python3
"""Host-side ftpwho exporter for ciosuseradd.

ProFTPd runs on the host, not in the compose stack, and its scoreboard is only
readable with the host's own `ftpwho` binary. This loop snapshots
`ftpwho -v -o json` every FTPWHO_INTERVAL seconds and writes it atomically to
FTPWHO_DIR/ftpwho.json, which is bind-mounted read-only into the backend
(served at GET /admin/ftpwho for the "Live Sessions" admin panel).

Each connection is also enriched with real numbers from the kernel ("io"), because
ProFTPd's scoreboard is useless for transfers under `UseSendFile on` (it barely
updates transfer bytes, so ftpwho shows 0% / no rate for hours):

  * bytes_out/bytes_in  — session totals from /proc/<pid>/io (wchar/rchar;
                          sendfile counts toward both)
  * rate_out/rate_in    — bytes/s over the last RATE_WINDOW seconds
  * last_io_ms          — when the session last moved any bytes (stall detection)
  * cmd_since_ms        — when the current command/args were first seen
  * file                — the file being transferred, from /proc/<pid>/fd + fdinfo:
                          path, size, offset (bytes done), pct, direction, approx.
                          Under sendfile the fd position stays at the REST offset,
                          so offset = start position + bytes read since the
                          transfer started; when the position itself moves (FTPS
                          read()+SSL_write path), it's used directly. Transfers
                          already running when the exporter started are estimated
                          and flagged approx=true.

Install: see ftpwho/ciosuseradd-ftpwho.service.
"""
import json
import os
import stat
import subprocess
import sys
import time
from collections import deque

OUT_DIR  = os.environ.get("FTPWHO_DIR", "/var/lib/ciosuseradd/ftpwho")
INTERVAL = float(os.environ.get("FTPWHO_INTERVAL", "1"))
FTPWHO   = os.environ.get("FTPWHO_BIN", "ftpwho")
OUT_PATH = os.path.join(OUT_DIR, "ftpwho.json")

RATE_WINDOW = 10   # seconds of history used for transfer rates
XFER_CMDS   = {"RETR": "down", "STOR": "up", "APPE": "up", "STOU": "up"}
# fds under these prefixes are never "the file being transferred"
NOT_DATA    = ("/dev/", "/proc/", "/run/", "/sys/", "/var/log/", "/var/lib/", "/etc/", "/usr/", "/tmp/", "/lib")


def _read_io(pid):
    try:
        with open(f"/proc/{pid}/io") as f:
            v = dict(line.split(": ") for line in f.read().splitlines() if ": " in line)
        return int(v["rchar"]), int(v["wchar"])
    except (OSError, KeyError, ValueError):
        return None


def _xfer_file(pid, direction):
    """(path, inode, size, pos) of the regular file a session is transferring, or None."""
    best = None
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return None
    for fd in fds:
        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
            if not target.startswith("/") or target.startswith(NOT_DATA):
                continue
            st = os.stat(f"/proc/{pid}/fd/{fd}")
            if not stat.S_ISREG(st.st_mode):
                continue
            with open(f"/proc/{pid}/fdinfo/{fd}") as f:
                info = dict(line.split(":\t", 1) for line in f.read().splitlines() if ":\t" in line)
            writing = int(info["flags"], 8) & 3 != 0
            if writing != (direction == "up"):
                continue
            cand = (target, st.st_ino, st.st_size, int(info["pos"]))
            if best is None or cand[2] > best[2]:
                best = cand
        except (OSError, KeyError, ValueError):
            continue
    return best


class IoTracker:
    """Per-pid state across snapshots: rate history, current command, current transfer."""

    def __init__(self):
        self.hist = {}      # pid -> deque[(t, rchar, wchar)]
        self.last_io = {}   # pid -> (ms, rchar, wchar)
        self.cmd = {}       # pid -> ((command, args), since_ms)
        self.xfer = {}      # pid -> dict(key, rchar0, base, pos_prev, pos_live, approx)
        self.started_ms = None

    def enrich(self, conns, now_ms):
        alive = set()
        t = now_ms / 1000
        if self.started_ms is None:
            self.started_ms = now_ms
        for c in conns:
            pid = c.get("pid")
            if not isinstance(pid, int):
                continue
            alive.add(pid)
            first_sight = pid not in self.cmd
            io = _read_io(pid)
            cmdkey = (c.get("command") or "", c.get("command_args") or "")
            prev = self.cmd.get(pid)
            if prev is None or prev[0] != cmdkey:
                self.cmd[pid] = (cmdkey, now_ms)
            # A command already running when the exporter started is only known to be
            # at least this old; anything that changed later was seen from its start.
            out = {"cmd_since_ms": self.cmd[pid][1],
                   "cmd_since_approx": self.cmd[pid][1] - self.started_ms < 5000}
            if io:
                rchar, wchar = io
                h = self.hist.setdefault(pid, deque())
                h.append((t, rchar, wchar))
                while len(h) > 2 and h[0][0] < t - RATE_WINDOW:
                    h.popleft()
                span = h[-1][0] - h[0][0]
                lio = self.last_io.get(pid)
                if lio is None or lio[1] != rchar or lio[2] != wchar:
                    lio = (now_ms, rchar, wchar)   # first sight counts as a lower bound
                    self.last_io[pid] = lio
                out.update({
                    "bytes_in": rchar, "bytes_out": wchar,
                    "rate_in": int((h[-1][1] - h[0][1]) / span) if span >= 2 else None,
                    "rate_out": int((h[-1][2] - h[0][2]) / span) if span >= 2 else None,
                    "last_io_ms": lio[0],
                })
                direction = XFER_CMDS.get(cmdkey[0])
                f = _xfer_file(pid, direction) if direction else None
                if f:
                    path, ino, size, pos = f
                    x = self.xfer.get(pid)
                    if x is None or x["key"] != (path, ino):
                        # Seen from its start (command began within the last few seconds,
                        # after the exporter was already watching) vs. already running
                        approx = first_sight or now_ms - self.cmd[pid][1] > 3000
                        x = {"key": (path, ino), "rchar0": rchar, "pos_prev": pos, "pos_live": False,
                             "approx": approx and direction == "down",
                             "base": pos + (rchar if approx and direction == "down" else 0)}
                        self.xfer[pid] = x
                    if pos != x["pos_prev"]:
                        x["pos_live"] = True
                        x["pos_prev"] = pos
                    if direction == "up" or x["pos_live"]:
                        offset = pos
                    else:
                        offset = x["base"] + (rchar - x["rchar0"])
                    if direction == "down":
                        offset = min(offset, size)
                    out["file"] = {
                        "path": path, "size": size, "offset": offset, "direction": direction,
                        "pct": round(100 * offset / size, 1) if direction == "down" and size else None,
                        "approx": bool(x["approx"] and not x["pos_live"]),
                    }
                else:
                    self.xfer.pop(pid, None)
            c["io"] = out
        for d in (self.hist, self.last_io, self.cmd, self.xfer):
            for pid in list(d):
                if pid not in alive:
                    del d[pid]


TRACKER = IoTracker()


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
        try:
            TRACKER.enrich(snap["connections"], snap["generated_ms"])
        except Exception as e:   # enrichment is best-effort; never lose the snapshot
            print(f"ftpwho-export: io enrichment failed: {e}", file=sys.stderr, flush=True)
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
