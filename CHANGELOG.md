# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- **Private FTP users**: admin-provisioned read/write accounts chrooted under a separate `PRIVATE_FTP_BASE_PATH` (not inside the public FTP root). Home folders are created by the backend (750, `FTP_UID:PRIVATE_FTP_GID`); deleting a user keeps the folder. Generated `ftpd_private.conf` uses `DefaultRoot ~ <PRIVATE_FTP_GROUP>` plus a deny-all on the base and a per-folder `AllowUser` lock. New admin panel, dashboard card, and Live Sessions class.
- **Automatic ProFTPd reload**: host-side `ciosuseradd-proftpd-reload.path`/`.service` (in `proftpd-reload/`) watch `ftpd_trusted.conf` and `ftpd_private.conf` and run a config test + graceful `systemctl reload proftpd` on change — new trusted/private users work immediately. Generated files are no longer rewritten when unchanged.
- **FTP Bans** (anonymous users only): host-side detector `ciosuseradd-ftpban` reads a dedicated ProFTPd session log and auto-bans anonymous IPs that idle-squat (`TimeoutNoTransfer`/`TimeoutIdle`), reconnect-storm or abort-loop, enforced with a dedicated nftables table (no ProFTPd reloads). Banned clients get an FTP `421` reply with a ban message configurable per ban type (with `{remaining}`/`{expires}`/`{ip}`/`{reason}` placeholders) from a built-in responder. A separate watchdog timer restarts the ban daemon if it hangs or its responder stops answering, and **fails open** (removes all firewall bans) if it can't be recovered; the panel shows the state with a Retry button. Admin panel with active bans, watchlist, top offenders, history, charts, per-IP detail, manual ban/unban/duration, dry-run mode, editable rules, escalation, whitelist and ports; **Ban IP** button on anonymous Live Sessions rows. New setting `FTPBAN_DIR`.
- **R/W Activity log** for trusted and private users: every upload, download, file delete, folder create/delete, rename/move, chmod and login (including failed attempts) is recorded from the ProFTPd log into `ftp_activity` (kept indefinitely), with history backfilled from the existing log. New panel with per-user summary, filters, pagination and CSV export, plus an **Activity** button on each trusted/private user.
- **IP whitelists** for both FTP Bans and Security Threats, each with its own tab (add IP/CIDR with a note, remove) and **Whitelist** buttons on ban/watchlist/offender/incident rows. FTP: never auto-banned, active auto bans lifted on add. Threats: no intrusion warning, lockout or auto bans, and IP bans don't apply.
- **"Wrong login page?" pointer**: optional `WRONG_PORTAL_NAME`/`WRONG_PORTAL_URL` show a prominent "Trying to get to X? Please go to URL" box on the admin login warning and ban messages.
- **Public overview time picker**: 1m, 5m, 1h, 12h, 24h, 1 week, 1 month, 1 year, All. It drives every activity section, including Top Files and Top IPs, which were always all-time before. Short ranges use finer chart buckets, per-minute/per-hour averages and faster auto-refresh (every 10s at 1m/5m).
- **Busiest-times heatmaps**: day-of-week × hour-of-day grids of downloads (or data) for FTP and for HTTP, in the viewer's local timezone, coloured green (quiet) to red (busy), with per-day and per-hour totals and peak/quietest hours. Own **Busiest Times** sidebar section (FTP Heatmap, HTTP Heatmap) and the same maps and tables on the public overview page. Time range: presets (24h–All) or a custom From/To picker. The FTP views also have an uploads heatmap (public: excluding private users), and every view ends with a Best & Worst Times table (best/worst time to download and upload: day + hour, plus best/worst day and hour overall).
- New settings: `PRIVATE_FTP_BASE_PATH`, `PRIVATE_FTP_GROUP`, `PRIVATE_FTP_GID` (dedicated host group required).

### Fixed
- FTP and HTTP log timestamps were stored as local time labelled UTC (offset dropped), shifting all FTP stats and live HTTP stats by 4–5h. Parsers now honour the offset; existing rows were migrated once (originals kept in `tz_fix_backup`).
- Live Sessions showed 0% and no speed for large downloads for hours: ProFTPd's scoreboard doesn't track bytes under sendfile. The ftpwho exporter now reads real progress, speed and last-data time from `/proc`; the panel shows %/size/ETA, a stall warning, and per-command duration.
- Logs database pinned at 100%+ CPU: the stats cache re-warmed ~80 multi-million-row aggregates every 4.5 minutes regardless of viewers, all in parallel, exhausting the connection pool (admin requests failed with "connection pool exhausted" and finished computes were discarded, so some stats were days old). Warmup now runs only at startup, cache TTLs scale with the time window (5 min → 1 h), background refreshes run two at a time, download stats no longer use `COUNT(DISTINCT)` (which spilled TBs of temp files), and `db_logs` gets tuned memory settings (new optional `LOGS_PG_*` settings).
- Removed 1.67M duplicate download rows created by repeated log-archive imports (HTTP 2026-05-31→06-10 and 06-23→06-26, FTP anonymous 2026-05-11); genuine repeated chunk requests kept. Removed rows kept in `dedupe_backup_*`.

### Changed
- Usernames are now checked for uniqueness across regular, trusted, and private users on every create path (previously regular registration didn't check trusted users).
- Public dashboard top files/users exclude private-user activity.

---

## [0.1.0] — 2026-10-03

### Added
- **Trusted FTP users**: admin-provisioned read/write accounts, each chrooted to its own directory under `FTP_BASE_PATH` via a generated `ftpd_trusted.conf` (`<IfUser>` blocks), with a separate `TRUSTED_FTP_GID` and a **Fix Perms** action
- **HTTP downloads site support**: `.htpasswd` generated from registered users (first line preserved as the shared public login), plus HTTP download tracking from the nginx log
- **Upload tracking**: FTP `STOR`/`APPE` recorded to `user_uploads`/`anon_uploads`
- **Archive ingestion**: rotated/compressed logs ingested once on startup, with progress shown in the new **DB Status** page
- **Public dashboard** (`/public.html`): read-only overview with masked IPs and usernames
- **Live Sessions**: real-time `ftpwho -v` view, fed by a host-side exporter (`ftpwho/`, systemd unit included)
- **Security**: admin intrusion detection with warn-then-ban, IP/username bans, multi-username detection
- Stale-while-revalidate stats cache for fast page loads
- `SITE_NAME`, `FTP_PUBLIC_HOST`, `PUBLIC_HTTP_USERNAME`, `TRUSTED_FTP_GID`, `HTPASSWD_DIR`, `HTTP_LOG_DIR`, `FTPWHO_DIR` settings

### Changed
- Removed all deployment-specific branding, hostnames, and paths from the code. Configure them through `.env` instead.
- Default `FTP_BASE_PATH` is now `/srv/ftp`

### Upgrading from 0.0.1
- Add the new variables from `.env.example` to your `.env`. To keep the old behaviour, set `SITE_NAME`, `FTP_PUBLIC_HOST`, and `PUBLIC_HTTP_USERNAME` to your previous values.
- Add `Include /etc/proftpd/ftpd_trusted.conf` to `proftpd.conf` if you plan to use trusted users.
- `docker compose up -d --build`

---

## [0.0.1] — 2026-05-12

Initial release.

### Features

#### User Management
- Self-service FTP account registration with username, email, and password
- Admin-created accounts — provision users directly from the dashboard without self-registration
- Per-user management: change email, reset password, add internal notes, enable/disable, delete
- `ftpd.passwd` regenerated atomically on every account change — no ProFTPd reload required
- Reserved username blocklist prevents registration of system, service, and admin-adjacent names
- User database export to JSON (includes bcrypt hashes for full restore capability)
- User database import from JSON — merge mode, skips existing usernames/emails

#### Admin Dashboard
- Dashboard overview with user counts and recent registrations
- Searchable and filterable user table with quick enable/disable actions
- Full audit log of every admin action with timestamp, IP address, and detail
- Admin credentials (username + password) stored in database, changeable via UI
- Credentials seeded from environment variables on first start only

#### Download Activity Tracking
- Dedicated `logtailer` container tails ProFTPd's `custom_user` ExtendedLog in real time
- Named-user downloads tracked with: timestamp, IP, username, full file path, bytes transferred
- Anonymous downloads tracked separately with: timestamp, IP, full file path, bytes transferred
- Active log filename configurable from the Settings panel — change takes effect in ~10 seconds, no restart needed
- Log tailer persists file position to a named Docker volume — survives full stack restarts without reprocessing
- Log retention: configurable nightly pruning with enable/disable toggle (default: 90 days, enabled)
- Paginated download tables with filter by username, IP, filename/path, and date range
- Top 10 files, users, and IPs shown per panel
- Full file paths displayed throughout (FTP root prefix stripped for readability)
- CSV export of user and anonymous download logs with current filters applied

#### Statistics
- Chart.js line chart: named vs anonymous downloads over time
- Chart.js bar chart: data transferred over time (MB)
- Chart.js horizontal bar: top files by download count
- Chart.js horizontal bar: top users by download count
- 1 / 7 / 30 / 90 day range selector
- Trend cards showing current period vs prior period with % change

#### Settings Panel
- Change admin password (requires current password confirmation)
- Change admin username
- Log file selector (filename within mounted log directory)
- Log retention toggle (enable/disable) + configurable day limit
- Tailer status display: current file, last write timestamp, total rows ingested
- Export user database as JSON
- Import user database from JSON
- Export user downloads as CSV
- Export anonymous downloads as CSV

#### Infrastructure
- Six Docker containers: nginx, frontend, backend, db, db_logs, logtailer
- Two isolated PostgreSQL instances: one for user data, one for download activity
- Three isolated Docker networks: internal, db (internal-only), db_logs (internal-only)
- Chart.js served locally — no external CDN dependencies
- Favicon support: drop `favicon.ico` or `favicon.png` into `frontend/static/` and rebuild

#### Security
- bcrypt password hashing at work factor 12
- JWT sessions (8-hour expiry, sessionStorage)
- Rate limiting at nginx and application layers (register: 5/min, admin login: 5/min, API: 30/min)
- Security headers: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CSP
- ProFTPd log directory mounted read-only into logtailer
- Logtailer has no access to user database network
- No API documentation exposed in production

---

[0.1.0]: https://github.com/paulmataruso/open_proftpd_admin/releases/tag/v0.1.0
[0.0.1]: https://github.com/paulmataruso/open_proftpd_admin/releases/tag/v0.0.1
