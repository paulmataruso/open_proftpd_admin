-- FTP Activity Log Schema
-- Applied automatically on first start via docker-entrypoint-initdb.d

-- Named user downloads
CREATE TABLE IF NOT EXISTS user_downloads (
    id          BIGSERIAL PRIMARY KEY,
    logged_at   TIMESTAMPTZ NOT NULL,
    ip_address  INET NOT NULL,
    username    TEXT NOT NULL,
    filepath    TEXT NOT NULL,
    filename    TEXT NOT NULL,
    bytes       BIGINT,
    source      TEXT NOT NULL DEFAULT 'ftp'   -- 'ftp' or 'http'
);

CREATE INDEX IF NOT EXISTS idx_ud_logged_at   ON user_downloads (logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_ud_username    ON user_downloads (username);
CREATE INDEX IF NOT EXISTS idx_ud_ip          ON user_downloads (ip_address);
CREATE INDEX IF NOT EXISTS idx_ud_user_time   ON user_downloads (username, logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_ud_filename    ON user_downloads (filename);
CREATE INDEX IF NOT EXISTS idx_ud_source      ON user_downloads (source);
CREATE INDEX IF NOT EXISTS idx_ud_source_time ON user_downloads (source, logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_ud_source_user ON user_downloads (source, username, logged_at DESC);

-- Anonymous downloads
CREATE TABLE IF NOT EXISTS anon_downloads (
    id          BIGSERIAL PRIMARY KEY,
    logged_at   TIMESTAMPTZ NOT NULL,
    ip_address  INET NOT NULL,
    filepath    TEXT NOT NULL,
    filename    TEXT NOT NULL,
    bytes       BIGINT,
    source      TEXT NOT NULL DEFAULT 'ftp'   -- 'ftp' or 'http'
);

CREATE INDEX IF NOT EXISTS idx_ad_logged_at   ON anon_downloads (logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_ad_ip          ON anon_downloads (ip_address);
CREATE INDEX IF NOT EXISTS idx_ad_filename    ON anon_downloads (filename);
CREATE INDEX IF NOT EXISTS idx_ad_source      ON anon_downloads (source);
CREATE INDEX IF NOT EXISTS idx_ad_source_time ON anon_downloads (source, logged_at DESC);

-- Named user uploads (FTP STOR/APPE)
CREATE TABLE IF NOT EXISTS user_uploads (
    id          BIGSERIAL PRIMARY KEY,
    logged_at   TIMESTAMPTZ NOT NULL,
    ip_address  INET NOT NULL,
    username    TEXT NOT NULL,
    filepath    TEXT NOT NULL,
    filename    TEXT NOT NULL,
    bytes       BIGINT,
    source      TEXT NOT NULL DEFAULT 'ftp'
);

CREATE INDEX IF NOT EXISTS idx_uu_logged_at   ON user_uploads (logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_uu_username    ON user_uploads (username);
CREATE INDEX IF NOT EXISTS idx_uu_ip          ON user_uploads (ip_address);
CREATE INDEX IF NOT EXISTS idx_uu_user_time   ON user_uploads (username, logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_uu_filename    ON user_uploads (filename);

-- Anonymous uploads
CREATE TABLE IF NOT EXISTS anon_uploads (
    id          BIGSERIAL PRIMARY KEY,
    logged_at   TIMESTAMPTZ NOT NULL,
    ip_address  INET NOT NULL,
    filepath    TEXT NOT NULL,
    filename    TEXT NOT NULL,
    bytes       BIGINT,
    source      TEXT NOT NULL DEFAULT 'ftp'
);

CREATE INDEX IF NOT EXISTS idx_au_logged_at   ON anon_uploads (logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_au_ip          ON anon_uploads (ip_address);
CREATE INDEX IF NOT EXISTS idx_au_filename    ON anon_uploads (filename);

-- Pre-computed stats cache (warmed by backend background task, TTL 5 minutes)
CREATE TABLE IF NOT EXISTS stats_cache (
    cache_key   TEXT PRIMARY KEY,
    data        JSONB NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tailer config / status (written by logtailer, read by backend)
CREATE TABLE IF NOT EXISTS tailer_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed defaults
INSERT INTO tailer_config (key, value) VALUES
    ('log_filename',          'full_user.log'),
    ('log_retention_days',    '90'),
    ('log_retention_enabled', 'true'),
    ('http_log_filename',     'http_downloads.log'),
    ('http_log_enabled',      'true'),
    ('tailer_status',         'starting'),
    ('tailer_last_write',     ''),
    ('tailer_pos',            '0'),
    ('http_tailer_pos',       '0'),
    ('tailer_total_rows',     '0'),
    ('upload_backfill_done',  'false')
ON CONFLICT (key) DO NOTHING;
