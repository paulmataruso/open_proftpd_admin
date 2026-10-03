-- Users table
CREATE TABLE IF NOT EXISTS users (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username           VARCHAR(64) UNIQUE NOT NULL,
    email              VARCHAR(255) UNIQUE NOT NULL,
    password_hash      TEXT NOT NULL,
    enabled            BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login         TIMESTAMPTZ,
    notes              TEXT,
    registered_from_ip VARCHAR(45)
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    username    VARCHAR(64),
    action      VARCHAR(64) NOT NULL,
    detail      TEXT,
    ip_address  VARCHAR(45),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_log_username_idx  ON audit_log(username);
CREATE INDEX IF NOT EXISTS audit_log_created_at_idx ON audit_log(created_at);

-- Admin configuration (credentials + system settings)
-- Seeded on first backend startup from environment variables.
-- After that, managed entirely via the admin UI.
CREATE TABLE IF NOT EXISTS admin_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Default rows are inserted by the backend on first start, not here,
-- because the hashed password requires bcrypt which is a Python concern.

-- Trusted FTP users (per-user chroot with read/write access)
-- Existing installs: the backend auto-creates this table on next restart via SQLAlchemy create_all.
CREATE TABLE IF NOT EXISTS trusted_ftp_users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(64) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    ftp_home_dir  TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes         TEXT
);

-- Admin portal intrusion attempts
-- Tracks non-admin users who attempt to log in to the admin portal.
CREATE TABLE IF NOT EXISTS admin_intrusion_attempts (
    id                 BIGSERIAL PRIMARY KEY,
    ip_address         VARCHAR(45) NOT NULL,
    username_attempted VARCHAR(64),
    matched_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    warning_sent_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    escalated_at       TIMESTAMPTZ,
    account_disabled   BOOLEAN NOT NULL DEFAULT false,
    reviewed           BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS intrusion_ip_idx ON admin_intrusion_attempts(ip_address);
CREATE INDEX IF NOT EXISTS intrusion_reviewed_idx ON admin_intrusion_attempts(reviewed);

-- Banned IP addresses (auto-banned after escalation or manually by admin)
CREATE TABLE IF NOT EXISTS banned_ips (
    id         BIGSERIAL PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reason     TEXT,
    banned_by  VARCHAR(16) NOT NULL DEFAULT 'auto',
    notes      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS banned_ips_ip_idx ON banned_ips(ip_address);

-- Banned usernames (auto-banned after escalation or manually by admin)
CREATE TABLE IF NOT EXISTS banned_usernames (
    id         BIGSERIAL PRIMARY KEY,
    username   VARCHAR(64) UNIQUE NOT NULL,
    reason     TEXT,
    banned_by  VARCHAR(16) NOT NULL DEFAULT 'auto',
    notes      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS banned_usernames_username_idx ON banned_usernames(username);
