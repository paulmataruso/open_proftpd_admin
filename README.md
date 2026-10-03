# FTP User Manager

A self-hosted, fully Dockerized web portal for managing **ProFTPd virtual users** and an **nginx HTTP downloads site** (`.htpasswd`), with real-time download/upload tracking, a public stats page, and a live view of who is connected to the FTP server right now.

Users self-register (or are provisioned by an admin), and the system automatically syncs credentials to ProFTPd's virtual user file and nginx's `.htpasswd`. Admins get a dashboard for user management, audit logs, download/upload statistics, live sessions, and abuse controls.

> ProFTPd and your public downloads nginx are **not** part of this stack. They keep running on the host as normal system services. This stack writes the config files they read (`ftpd.passwd`, `ftpd_trusted.conf`, `.htpasswd`) and ingests their logs.

---

## Features

### Accounts
- **Self-service registration**: users sign up with username, email, and password
- **Admin-created accounts**: provision users directly from the dashboard
- **Two FTP user classes**:
  - **Registered users**: read-only FTP, chrooted to the shared FTP root, plus HTTP basic-auth access to the downloads site
  - **Trusted FTP users**: admin-provisioned, full read/write, each chrooted to their own directory under `FTP_BASE_PATH`
- **Automatic sync**: `ftpd.passwd`, `ftpd_trusted.conf`, and `.htpasswd` are regenerated atomically on every account change
- **No Linux system accounts**: all virtual users map to a single FTP system UID
- **Reserved username blocklist**: system, service, and admin-adjacent names can't be registered
- **User database backup**: export all accounts (including hashed passwords) to JSON and import them back to restore

### Activity tracking & stats
- **FTP and HTTP download/upload logging**: a dedicated `logtailer` container tails ProFTPd's ExtendedLog and your nginx downloads log into a separate PostgreSQL database
- **Archive ingestion**: rotated logs (`.gz`, `.tar.gz`, …) in the log directories are ingested once on startup, so you get history from before the stack existed
- **Registered vs anonymous split**: separate pages for registered-user downloads, anonymous downloads, uploads, and combined stats, for both FTP and HTTP
- **Charts & stats**: Chart.js charts with selectable ranges, trend cards, top files/users/IPs
- **Fast stats**: pre-computed, stale-while-revalidate stats cache
- **CSV export**: download any log view as CSV with the current filters applied
- **Log retention**: optional nightly pruning, or keep everything forever

### Live FTP sessions
- **Real-time `ftpwho` view**: every connected session with user, IP, protocol (FTP/FTPS), current file, progress, transfer rate and connection time, refreshed every 2 seconds
- Filter by transfers, downloads, uploads, or idle, and by user class; free-text search over user, IP, and file
- Fed by a tiny host-side exporter service (see [Live FTP sessions](#live-ftp-sessions-ftpwho))

### Public dashboard
- **`/public.html`**: an unauthenticated, read-only overview of download activity. IPs are masked to their first two octets and usernames show only their first and last character.

### Security & abuse controls
- **IP and username bans**, manual or automatic
- **Admin intrusion detection**: failed admin logins are logged, warned once, then banned
- **Multi-username detection**: flags IPs that try several different admin usernames
- **Rate limiting** at both the nginx and application layers
- bcrypt passwords, JWT sessions, CSP and security headers, isolated database networks, no API docs exposed

---

## Architecture

```
                    ┌──────────────────────────────────────┐
Internet ──► (TLS) ─►│ nginx (reverse proxy, rate limits)   │
 reverse proxy      │                                      │
                    │  ┌──────────┐     ┌───────────────┐  │
                    │  │ frontend │     │    backend    │  │
                    │  │ (static) │     │   (FastAPI)   │  │
                    │  └──────────┘     └───────┬───────┘  │
                    │              ┌────────────┴────────┐ │
                    │              │   db    │  db_logs  │ │
                    │              │  (PG)   │   (PG)    │ │
                    │              └─────────┴─────▲─────┘ │
                    └────────────────────────────────┼─────┘
                                                     │
                    ┌────────────────────────────────┴─────┐
                    │ logtailer (tails host log dirs)      │
                    └──────────────────────────────────────┘
                         ▲ read-only                 ▲ read-only
              ProFTPd log dir (host)       nginx log dir (host)

  Host files written by backend:  ftpd.passwd · ftpd_trusted.conf · .htpasswd
  Host files read by backend:     FTPWHO_DIR/ftpwho.json  (from ftpwho exporter)
```

| Container | Image | Purpose |
|---|---|---|
| `nginx` | `nginx:alpine` | Reverse proxy, rate limiting, security headers |
| `frontend` | Custom | Static admin/registration SPA (`index.html`) and public dashboard (`public.html`) |
| `backend` | Custom | FastAPI REST API; writes `ftpd.passwd`, `ftpd_trusted.conf`, `.htpasswd`; stats queries |
| `db` | `postgres:16-alpine` | Users, trusted users, admin config, audit log, bans, intrusion attempts |
| `db_logs` | `postgres:16-alpine` | Download/upload activity and stats cache (isolated from `db`) |
| `logtailer` | Custom | Tails the ProFTPd and nginx log directories into `db_logs` |

One small component runs **on the host** instead of in compose: the `ftpwho` exporter (`ftpwho/`). ProFTPd's scoreboard can only be read by the host's own `ftpwho` binary.

---

## Requirements

- Docker Engine 24+ and Docker Compose v2
- ProFTPd on the host with `mod_auth_file` and `mod_ifsession` (both standard in Ubuntu/Debian packages)
- ProFTPd ExtendedLog in the `custom_user` format (see [ProFTPd Configuration](#proftpd-configuration))
- Optional: nginx on the host serving the HTTP downloads site with basic auth, logging in the format below
- Optional: Python 3 on the host for the live-sessions exporter

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/paulmataruso/open_proftpd_admin.git
cd open_proftpd_admin
```

### 2. Configure the environment

```bash
cp .env.example .env
nano .env
```

Fill in every `CHANGEME` value, then set the paths for your host. At minimum:

```bash
# Generate a strong JWT secret
openssl rand -hex 32

# Find your FTP system user's UID/GID
id anonftp
```

See [Environment Variables](#environment-variables) for the full reference.

### 3. Configure ProFTPd

See [ProFTPd Configuration](#proftpd-configuration).

### 4. (Optional) Configure the HTTP downloads site

See [HTTP downloads site](#http-downloads-site-optional).

### 5. (Optional) Branding

- Set `SITE_NAME` (and optionally `FTP_PUBLIC_HOST`) in `.env`.
- Replace `frontend/static/favicon.ico` / `favicon.png` with your own logo (see `frontend/static/FAVICON_README.txt`).

### 6. Start the stack

```bash
docker compose up -d
```

### 7. (Optional) Install the live-sessions exporter

See [Live FTP sessions](#live-ftp-sessions-ftpwho).

### 8. Verify

```bash
docker compose ps
curl http://127.0.0.1:${LISTEN_PORT}/api/health
```

The web UI is at `http://BIND_IP:LISTEN_PORT/`, and the public dashboard is at `/public.html`.

---

## ProFTPd Configuration

### Step 1: Add the required directives to proftpd.conf

Merge these into `/etc/proftpd/proftpd.conf` carefully if some of the directives already exist.

```apache
# ── Virtual user authentication ───────────────────────────────────────────────
AuthOrder          mod_auth_file.c mod_auth_unix.c
AuthUserFile       /etc/proftpd/ftpd.passwd        # FTPD_PASSWD_DIR + /ftpd.passwd
RequireValidShell  off

# Trusted (R/W) user chroots, generated by the backend
Include            /etc/proftpd/ftpd_trusted.conf

# ── TLS (strongly recommended) ────────────────────────────────────────────────
<IfModule mod_tls.c>
  TLSEngine                on
  TLSLog                   /var/log/proftpd/tls.log
  TLSProtocol              TLSv1.2 TLSv1.3
  TLSRSACertificateFile    /etc/letsencrypt/live/ftp.example.com/fullchain.pem
  TLSRSACertificateKeyFile /etc/letsencrypt/live/ftp.example.com/privkey.pem
  TLSVerifyClient          off
  TLSRequired              on
</IfModule>

# ── Activity logging (required for download/upload tracking) ──────────────────
<IfModule mod_log.c>
  LogFormat custom_user "%t|%a|%u|%f|%m|%s|%b"
  ExtendedLog /var/log/proftpd/full_user.log ALL custom_user
</IfModule>

# Recommended: uploads land group/world-readable so the web server can serve them
Umask 002 002
```

| Field | Meaning | Example |
|---|---|---|
| `%t` | Timestamp | `[11/May/2026:18:04:13 +0000]` |
| `%a` | Client IP | `203.0.113.10` |
| `%u` | Authenticated username | `testuser`, `anonftp`, or `-` |
| `%f` | File path | `/srv/ftp/vendor/file.tar.gz` |
| `%m` | FTP command | `RETR`, `STOR`, `APPE`, … |
| `%s` | Response status | `226` = transfer complete |
| `%b` | Bytes transferred | `6139031` |

### Step 2: Deploy the virtual users fragment

```bash
sudo cp proftpd/virtualusers.conf /etc/proftpd/conf.d/virtualusers.conf
sudo nano /etc/proftpd/conf.d/virtualusers.conf   # replace /path/to/your/ftp/root
```

This sets `DefaultRoot` to the FTP root (read/list only) and allows uploads (but not delete or rename) in `upload/`.

### Step 3: Test and reload

```bash
sudo proftpd --configtest
sudo systemctl reload proftpd
```

### How ProFTPd picks up changes

- **`ftpd.passwd`** is read fresh on every login. New, changed, or disabled users take effect immediately.
- **`ftpd_trusted.conf`** is only parsed when ProFTPd starts or reloads. After you **add a trusted user**, run `sudo systemctl reload proftpd`. A reload is a graceful SIGHUP and doesn't drop active transfers.

### Trusted users: home directory permissions

A new trusted user's home directory (`FTP_BASE_PATH/<home_dir>`) must exist on the host. Once it does, click **Fix Perms** on the user in the admin UI. That recursively chowns the directory to `FTP_UID:TRUSTED_FTP_GID`; until then the user's uploads fail with `550 Permission denied`.

### Download/upload classification

| Username in log | Recorded as |
|---|---|
| `anonftp` (FTP) or `-` (HTTP) | Anonymous |
| `PUBLIC_HTTP_USERNAME` (HTTP) | Anonymous (it's the shared public login) |
| Any other username | Registered user |

Only completed transfers are recorded: FTP status `226`, and HTTP `GET` with status `200`/`206`. FTP `RETR` counts as a download; `STOR`/`APPE` count as uploads. If your anonymous FTP user isn't `anonftp`, change `ANON_USER` in `logtailer/tailer.py` and rebuild the logtailer.

---

## HTTP downloads site (optional)

If you serve the same file tree over HTTP with nginx basic auth:

1. Point `HTPASSWD_DIR` at the directory holding the site's `.htpasswd`. The backend keeps the file's **first line** (your shared public login, e.g. `public:<hash>`) untouched and rewrites every other line from the enabled registered users.
2. Set `PUBLIC_HTTP_USERNAME` to that shared login's username, so its traffic is counted as anonymous.
3. Have nginx log downloads in this pipe-delimited format. The logtailer also understands the standard `combined` format for older archives.

```nginx
log_format http_dl '$time_iso8601|$remote_addr|$remote_user|$request_method|$request_uri|$status|$body_bytes_sent';
access_log /var/log/nginx/http_downloads.log http_dl;
```

The filename is configurable in **Settings** (default `http_downloads.log`, inside `HTTP_LOG_DIR`).

---

## Live FTP sessions (ftpwho)

The **Live Sessions** page under *FTP Activity* shows `ftpwho -v` data in near-real-time. ProFTPd's scoreboard has to be read on the host, so a small exporter there writes a JSON snapshot every second, and the backend serves that snapshot to the UI.

Install it on the ProFTPd host as root:

```bash
sudo install -m 755 ftpwho/ftpwho-export.py /usr/local/sbin/ciosuseradd-ftpwho-export
sudo cp ftpwho/ciosuseradd-ftpwho.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ciosuseradd-ftpwho
```

The exporter writes to `/var/lib/ciosuseradd/ftpwho/ftpwho.json` by default. If you change that path, change it both in the unit file (`FTPWHO_DIR`) and in `.env` (`FTPWHO_DIR`), then run `docker compose up -d backend`.

Notes:
- ProFTPd only refreshes per-transfer byte counters every so often, so the rates shown are **averages since each transfer started**, the same figure as ftpwho's own KB/s.
- If the exporter isn't running, the page shows *Offline* or *Stale* instead of failing.

---

## Environment Variables

Copy `.env.example` to `.env`. Every variable is documented inline there; the main ones are below.

### Databases

| Variable | Example | Description |
|---|---|---|
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | `ciosuseradd` / `ftpadmin` / — | User-management database |
| `LOGS_POSTGRES_DB` / `LOGS_POSTGRES_USER` / `LOGS_POSTGRES_PASSWORD` | `ftplogs` / `logsadmin` / — | Activity-log database (use a different password) |

### Application

| Variable | Example | Description |
|---|---|---|
| `SECRET_KEY` | `openssl rand -hex 32` | JWT signing key, 32+ characters |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / — | Initial admin credentials, **used on first start only**. Change them later in **Settings**. |
| `SITE_NAME` | `FTP User Manager` | Name shown in page titles and headers |
| `FTP_PUBLIC_HOST` | `ftp.example.com` | Optional; shown as the connection host on the registration page |
| `PUBLIC_HTTP_USERNAME` | `public` | Shared public HTTP login (first line of `.htpasswd`); counted as anonymous and can't be registered |

### ProFTPd integration

| Variable | Example | Description |
|---|---|---|
| `FTP_UID` / `FTP_GID` | `1001` / `1001` | UID/GID for registered + anonymous virtual users (`id anonftp`) |
| `TRUSTED_FTP_GID` | `33` | GID for trusted users, so their uploads are group-owned by the web server (`getent group www-data`) |
| `FTPD_PASSWD_DIR` | `/etc/proftpd` | Host directory for `ftpd.passwd` and `ftpd_trusted.conf` |
| `FTP_BASE_PATH` | `/srv/ftp` | Host FTP root; trusted users live in subdirectories of it |
| `FTP_LOG_DIR` | `/var/log/proftpd` | ProFTPd log **directory** (mounted read-only) |
| `FTPWHO_DIR` | `/var/lib/ciosuseradd/ftpwho` | Where the host ftpwho exporter writes its snapshot (mounted read-only) |

### HTTP site

| Variable | Example | Description |
|---|---|---|
| `HTPASSWD_DIR` | `/etc/nginx` | Host directory containing `.htpasswd` |
| `HTTP_LOG_DIR` | `/var/log/nginx` | nginx log **directory** (mounted read-only) |

### Network

| Variable | Example | Description |
|---|---|---|
| `ALLOWED_ORIGINS` | `https://ftp.example.com` | CORS origins (use `*` for testing only) |
| `BIND_IP` | `127.0.0.1` | IP the nginx container binds to |
| `LISTEN_PORT` | `8222` | Port the nginx container listens on |

After editing `.env`, run `docker compose up -d <service>` to apply it; no rebuild is needed. After editing source code, run `docker compose up -d --build <service>`.

---

## Reverse Proxy

Put a TLS-terminating reverse proxy (Nginx Proxy Manager, Caddy, Traefik, …) in front of `http://BIND_IP:LISTEN_PORT`. Once HTTPS works, set `ALLOWED_ORIGINS` to your public HTTPS origin and run `docker compose up -d backend`.

If your proxy adds its own headers and you see CSP errors in the browser console, add:

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
```

---

## Admin Dashboard

| Section | Description |
|---|---|
| **General Overview / Dashboard** | Combined FTP + HTTP activity, user counts, recent registrations |
| **All Users / User Detail** | Search, enable/disable, reset password, email, notes, delete, per-user download history |
| **Trusted FTP** | Create R/W users with their own home directory; fix permissions |
| **Audit Log** | Every admin action with timestamp and IP |
| **Live Sessions** | Real-time ftpwho view of connected FTP sessions |
| **FTP Downloads / Uploads / Anonymous / Stats** | Paginated, filterable logs, top lists, charts |
| **HTTP Downloads / Anonymous / Stats** | Same for the HTTP downloads site |
| **Threats** | Admin intrusion attempts, IP/username bans, multi-username detection |
| **DB Status** | Log DB size, archive ingestion progress, tailer status |
| **Settings** | Admin credentials, log filenames, retention, user import/export |
| **Sync passwd** | Force-regenerate `ftpd.passwd`, `ftpd_trusted.conf`, and `.htpasswd` from the database |

---

## Directory Structure

```
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── main.py          # FastAPI routes
│   ├── config.py        # Settings from environment
│   ├── models.py        # SQLAlchemy models
│   ├── schemas.py       # Validation, reserved usernames, response schemas
│   ├── auth.py          # bcrypt, JWT, DB-backed admin credentials
│   ├── ftpfile.py       # ftpd.passwd + ftpd_trusted.conf writers
│   ├── httpfile.py      # .htpasswd writer
│   ├── logs.py          # db_logs queries, stats cache, retention, CSV export
│   └── database.py
├── frontend/
│   ├── index.html       # Registration + admin SPA
│   ├── public.html      # Public read-only dashboard
│   └── static/          # Chart.js, favicon
├── logtailer/
│   └── tailer.py        # FTP + HTTP log tailing and archive ingestion
├── ftpwho/
│   ├── ftpwho-export.py              # Host-side ftpwho → JSON exporter
│   └── ciosuseradd-ftpwho.service    # systemd unit for it
├── nginx/nginx.conf     # Reverse proxy, rate limits, security headers
├── db/                  # Schemas for db and db_logs
└── proftpd/virtualusers.conf  # Drop-in ProFTPd config
```

---

## Backup

```bash
# User database
docker compose exec db pg_dump -U $POSTGRES_USER $POSTGRES_DB > backup_users_$(date +%Y%m%d).sql
docker compose exec -T db psql -U $POSTGRES_USER $POSTGRES_DB < backup_users.sql

# Activity log database
docker compose exec db_logs pg_dump -U $LOGS_POSTGRES_USER $LOGS_POSTGRES_DB > backup_logs_$(date +%Y%m%d).sql
docker compose exec -T db_logs psql -U $LOGS_POSTGRES_USER $LOGS_POSTGRES_DB < backup_logs.sql
```

You can also export and import user accounts as JSON (bcrypt hashes included) from **Settings**. Import merges: existing usernames and emails are skipped.

---

## Updating

```bash
git pull
docker compose up -d --build
```

Check the [CHANGELOG](CHANGELOG.md) for manual steps between versions.

---

## Troubleshooting

**`ftpd.passwd` / `.htpasswd` not being written**
```bash
docker compose logs backend | grep -i -E 'passwd|htpasswd'
docker compose exec backend ls -la /ftpshared/ /httpshared/
```

**A new trusted user can log in but lands in the wrong directory**: run `sudo systemctl reload proftpd` so ProFTPd re-reads `ftpd_trusted.conf`.

**A trusted user gets `550 Permission denied` on upload**: click **Fix Perms** for that user.

**A file or folder is visible to some users but not others**: check its mode on the host with `stat -c '%U:%G %a %n' <path>`. Files copied in as root outside FTP often lack the world-read bit.

**Logtailer not picking up activity**
```bash
docker compose logs logtailer
docker compose exec logtailer ls -la /logs/ftp /logs/http
tail -5 /var/log/proftpd/full_user.log    # must be 7 pipe-delimited fields
```

**Live Sessions shows *Offline* or *Stale***
```bash
systemctl status ciosuseradd-ftpwho
cat /var/lib/ciosuseradd/ftpwho/ftpwho.json | head -c 300
```

**Charts not loading or CSP errors**: see [Reverse Proxy](#reverse-proxy).

---

## License

MIT
