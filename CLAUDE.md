# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

A self-hosted, Dockerized web portal for managing ProFTPd virtual users and an HTTP downloads site (nginx `.htpasswd`), with real-time download/upload activity tracking. Users self-register or are admin-provisioned; admins get a dashboard for user management, audit logs, download/upload stats, and abuse controls (IP/username bans, intrusion detection).

**Crucial fact:** ProFTPd and the public-facing downloads nginx are **not** part of this docker-compose stack — they run as system services directly on the host (`systemctl {reload,status} proftpd`). This stack only *generates the config files those services read* (`ftpd.passwd`, `ftpd_trusted.conf`, `.htpasswd`) and *ingests their logs*. Don't look for ProFTPd inside a container. The one piece of this project that runs **on the host, outside compose**, is the ftpwho exporter (`ciosuseradd-ftpwho.service`, see *Live FTP sessions* below).

## Commands

```bash
docker compose up -d              # start/update the stack
docker compose build <service>    # rebuild an image after editing its source
docker compose up -d <service>    # recreate a container after editing .env or docker-compose.yml
docker compose logs -f <service>  # tail logs (backend, logtailer, nginx, db, db_logs, frontend)
docker compose ps
```

**`docker compose up -d <service>` alone does NOT pick up source code changes.** `backend/Dockerfile` and `logtailer/Dockerfile` `COPY . .` at build time, so editing anything under `backend/` or `logtailer/` requires `docker compose build <service>` before `up -d` (or `up -d --build`). A plain `.env`/`docker-compose.yml`-only change just needs `up -d <service>` — no rebuild, since env vars are injected at container-create time.

There is no test suite or linter configured in this repo.

**Forcing a config regeneration without a DB write:** `POST /admin/sync` (admin JWT required) re-runs `regenerate_ftpd_passwd()` + `regenerate_ftpd_trusted_conf()` + `regenerate_htpasswd()` against current DB state and current `settings` — use it after changing `FTP_UID`/`FTP_GID`/`TRUSTED_FTP_GID` in `.env` and restarting `backend`, to rewrite existing users' passwd-file entries without touching each one via the UI. The `/docs` endpoint is disabled and the backend isn't exposed on a host port directly (only via the `nginx` container's `/api/` proxy), so calling admin endpoints ad hoc from the host means `docker exec ciosuseradd_backend python3 -c '...'` (or `curl`) against `http://127.0.0.1:8000` from inside the container — plain `wget` busybox inside the alpine image doesn't support JSON POST bodies cleanly, `python3 -c` with `urllib.request` does.

## Architecture

### Containers and what they own

| Container | Owns |
|---|---|
| `nginx` | Reverse proxy, rate limiting, security headers, routes `/api/*` → backend, `/` → frontend |
| `frontend` | Static nginx serving `index.html` (auth'd admin/registration SPA) and `public.html` (unauth'd read-only dashboard) — `frontend/Dockerfile` COPYs each file individually, so a new frontend file needs an explicit `COPY` line added or it 404s silently |
| `backend` | FastAPI: all business logic, `ftpd.passwd`/`ftpd_trusted.conf`/`.htpasswd` generation, stats queries |
| `db` | Postgres — `users`, `trusted_ftp_users`, `admin_config`, `audit_log`, ban/intrusion tables |
| `db_logs` | Postgres — download/upload activity, isolated from `db` (separate network) |
| `logtailer` | Tails ProFTPd + nginx-downloads log files (host dirs, mounted read-only) into `db_logs` |

Three Docker networks: `internal` (nginx/frontend/backend), `db` (backend/db, internal-only), `db_logs` (backend/logtailer/db_logs, internal-only). `logtailer` has no route to `db` or to `internal`.

### Two FTP user classes — always handle them separately

- **Regular `User`** (table `users`): self-registered or admin-created, read-only FTP (chrooted to the global FTP root via `DefaultRoot` in `proftpd/virtualusers.conf`), also gets HTTP basic-auth access via `.htpasswd`.
- **`TrustedFtpUser`** (table `trusted_ftp_users`): admin-provisioned, full read/write, chrooted to their own directory under `FTP_BASE_PATH/<ftp_home_dir>` via a generated `<IfUser>` block.

`backend/ftpfile.py`'s `regenerate_ftpd_passwd()` writes both into one `ftpd.passwd`, but in **two separate loops** with separate GID sourcing (see below) — when touching UID/GID or permission logic, don't assume a single setting governs both classes.

`sync(db)` in `backend/main.py` is the central choke point: called after every `User`/`TrustedFtpUser` create/update/delete, it regenerates `ftpd.passwd` + `ftpd_trusted.conf` + `.htpasswd` atomically (temp file + rename). If you add a new mutation path for either table, call `sync(db)` at the end of it.

### ProFTPd integration has two different refresh semantics

1. **`ftpd.passwd`** (`AuthUserFile`, read via `mod_auth_file`) — read fresh **per login**. A `/admin/sync` (or any action that triggers `sync()`) is immediately live for the next connection; no ProFTPd restart needed.
2. **`ftpd_trusted.conf`** (`<IfUser>` chroot blocks, `Include`d from the static `/etc/proftpd/proftpd.conf`) — parsed only at **ProFTPd startup/reload**. A brand-new trusted user (or any change to which `<IfUser>` blocks exist) needs `systemctl reload proftpd` on the host before it takes effect, even though `ftpd.passwd` itself is already updated. `systemctl reload` is a graceful SIGHUP — it does not drop active transfers, and is the documented, expected way to apply this (see `proftpd/virtualusers.conf` header comments).

A freshly-created trusted-user home directory is owned `root:root` by default — the user's first `STOR`/`MKD` will get `550 Permission denied` until an admin runs `fix-permissions` (or manually chowns it) once.

### Ownership model for uploads (`FTP_UID`/`FTP_GID`/`TRUSTED_FTP_GID`)

- `settings.ftp_uid` / `settings.ftp_gid` (env `FTP_UID`/`FTP_GID`) apply **only** to regular + anonymous FTP users. They're read-only and can't create new content, so this GID choice doesn't affect upload ownership.
- `settings.trusted_ftp_gid` (env `TRUSTED_FTP_GID`, default `33`/www-data) is a **separate** setting used only for trusted users' `ftpd.passwd` lines, so their uploads land group-owned by the web server and stay readable by it — without touching regular/anon users' GID. Both classes share the same UID.
- `POST /admin/trusted/{id}/fix-permissions` recursively `chown`s an existing trusted user's *entire* home tree to `ftp_uid:trusted_ftp_gid` (not just the top-level directory) and `chmod`s directories `755`. Use it once right after creating a trusted user's home folder on the FTP host (see the permission-denied note above), and again if `TRUSTED_FTP_GID` is ever changed, to retroactively fix pre-existing uploads — new uploads after a `TRUSTED_FTP_GID` change + resync are correct automatically, no fix-permissions needed going forward.

### Live FTP sessions (ftpwho)

The admin "Live Sessions" panel (`panel-ftp-live` in `index.html`) shows `ftpwho -v` data in near-real-time. ProFTPd's scoreboard (`/run/proftpd.scoreboard`) can only be read reliably by the host's own `ftpwho` binary, so the data path is:

1. **Host:** `ftpwho/ftpwho-export.py` (installed as `/usr/local/sbin/ciosuseradd-ftpwho-export`, run by `ftpwho/ciosuseradd-ftpwho.service` → `/etc/systemd/system/`) runs `ftpwho -v -o json` every second and atomically writes `FTPWHO_DIR/ftpwho.json` (default `/var/lib/ciosuseradd/ftpwho`), wrapped with `generated_ms`/`ok`/`error`. Editing the script in the repo does nothing until it's re-copied to `/usr/local/sbin/` and `systemctl restart ciosuseradd-ftpwho`.
2. **Backend:** `FTPWHO_DIR` is bind-mounted read-only at `/ftpwho`; `GET /admin/ftpwho` (admin JWT) reads the file, normalizes each connection (`state` = download/upload/idle/command/auth, `user_class` = anon/registered/trusted/other via a lookup against `users`/`trusted_ftp_users`) and flags `stale` if the snapshot is >10s old. A missing file returns `ok:false` with an "is the exporter running?" error rather than a 5xx.
3. **Frontend:** polls every 2s only while the panel is open (`startLive`/`stopLive`, wired into `navTo`), pauses when the tab is hidden, and ticks elapsed timers client-side.

Gotchas:
- ftpwho 1.3.8's JSON field `transfer_duration_ms` is actually **microseconds** — the backend divides by 1000 to get `transfer_ms`. `connected_since_ms`/`idle_since_ms`/`started_ms` are real milliseconds.
- ProFTPd only updates per-transfer byte counters in the scoreboard every so often (roughly once a minute with sendfile), so a rate computed from the change between polls is meaningless. The displayed rate is `transfer_bytes / transfer_ms`, i.e. the average since the transfer started, which is the same as ftpwho's own KB/s.
- nginx gives `/api/admin/ftpwho` its own `ftpwho` limit_req zone (120 r/m). Don't route it through the shared `/api/` zone (30 r/m), or the 2s poller would starve the rest of the admin UI.

### Download/upload activity pipeline

`logtailer/tailer.py` runs two threads (FTP, HTTP), each tailing a host log file/directory (mounted read-only) and writing rows to `db_logs`, tagged `source='ftp'|'http'`. On startup it also ingests any rotated/archived log files (`.gz`/`.tar.gz`/etc.) found in the same directory, tracked in `processed_archives` so each archive is only ingested once.

- FTP log line format: `[timestamp]|IP|USER|PATH|COMMAND|STATUS|BYTES` (pipe-delimited, 7 fields) — only `STATUS==226` rows are kept; `RETR` → downloads, `STOR`/`APPE` → uploads.
- HTTP log: tries the custom pipe format first (`parse_http_line`), falls back to standard nginx combined format (`parse_nginx_access_line`) for historical archives that predate the custom format.
- `username == 'anonftp'` (FTP) or `'-'` (HTTP) → `anon_downloads`/`anon_uploads`; anything else → `user_downloads`/`user_uploads`.

**Registered-vs-anonymous classification gotcha (`backend/logs.py`):** the shared public HTTP credential (`settings.public_http_username`, env `PUBLIC_HTTP_USERNAME`, the preserved first line of `.htpasswd`) is the *public* downloads login and is treated as anonymous everywhere in the UI, but it lands in `user_downloads` (not `anon_downloads`) because it authenticates like a named user. Any query that needs to split "registered users" from "anonymous" **must** go through `_registered_downloads_sql(source)` / `_anon_downloads_sql(source)` — never query `user_downloads`/`anon_downloads` directly for that split, or HTTP anonymous traffic gets miscounted as registered.

**Stats caching:** `stats_cache` table in `db_logs`, stale-while-revalidate via a shared `_swr(key, compute)` helper in `logs.py` — a value past its 5-minute TTL is still returned immediately while a background thread recomputes and updates the cache; only a true cache-miss (`data is None`) blocks synchronously. All cached stats functions route through `_swr`; a new cached function should too rather than reinventing the cache dance. Cache values are JSON — `_json_safe()` converts `Decimal` (from Postgres `SUM(bigint)`) to `int`/`float` before serializing; don't reintroduce `json.dumps(..., default=str)` for cached numeric fields, since a `Decimal` silently round-tripping as a JSON *string* breaks frontend arithmetic (`a + b` becomes string concatenation) without erroring anywhere.

**Public dashboard** (`frontend/public.html`, `GET /public/overview/*` routes): reuses the exact same cached `logs.py` functions as the authenticated `/admin/logs/*` routes (so admin and public data are never computed differently), then masks IP/username **only in the route handler** — `_mask_ip()` blanks the last two IPv4 octets, `_mask_username()` keeps first+last char. Never add a field to a public route that isn't masked on the way out.

## Config

- `.env` is gitignored; `.env.example` is the template — keep both in sync when adding a new setting.
- `FTPD_PASSWD_DIR`, `FTP_BASE_PATH`, `HTPASSWD_DIR`/`HTTPASSWD_DIR` are **host** paths, bind-mounted into `backend` as `/ftpshared`, `/ftpbase`, `/httpshared` respectively.
- `FTP_LOG_DIR` / `HTTP_LOG_DIR` are **host** paths, bind-mounted **read-only** into `logtailer`.
- `FTPWHO_DIR` is a **host** path, bind-mounted **read-only** into `backend` at `/ftpwho`. It must match `Environment=FTPWHO_DIR=` in the systemd unit.
- **Keep the repo generic — no deployment-specific values in code.** Site name, public FTP host, and the public HTTP login come from `SITE_NAME`/`FTP_PUBLIC_HOST`/`PUBLIC_HTTP_USERNAME`, served unauthenticated by `GET /public/site` and loaded into the `SITE` object on both frontends (`siteReady` promise; initial data loads wait on it). The frontends strip `SITE.ftp_base_path` from displayed file paths. Never hardcode a hostname, path, IP, or username in code or docs; put real values only in `.env`. `PUBLIC_HTTP_USERNAME` is embedded directly in SQL in `logs.py`, which is why `config.py` validates it against `[A-Za-z0-9_.-]`.
- `ADMIN_USERNAME`/`ADMIN_PASSWORD` only seed `admin_config` on first boot; after that, admin credentials live in the DB and are managed via the Settings panel — changing the env vars later has no effect.
