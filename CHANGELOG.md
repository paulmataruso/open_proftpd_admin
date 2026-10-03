# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/paulmataruso/pftpuseradd/releases/tag/v0.1.0
[0.0.1]: https://github.com/paulmataruso/pftpuseradd/releases/tag/v0.0.1
