import re
from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Main user-management database (PostgreSQL)
    database_url: str

    # FTP activity log database (separate PostgreSQL instance)
    logs_database_url: str

    # Auth — used only to seed admin_config on first start.
    # After first start, credentials are managed via the admin UI.
    secret_key: str
    admin_username: str = "admin"
    admin_password: str = "changeme"

    # ProFTPd passwd file
    ftpd_passwd_path: str = "/ftpshared/ftpd.passwd"
    ftp_uid: int = 1001
    ftp_gid: int = 33

    # Trusted (R/W) FTP users get their own GID so uploaded files/folders land
    # group-owned by www-data and stay readable by the web server. Regular
    # (read-only) and anonymous users are unaffected — they keep ftp_gid above.
    trusted_ftp_gid: int = 33

    # Trusted FTP user config
    ftp_base_path: str = "/srv/ftp"
    ftp_base_mount: str = "/ftpbase"          # container-side mount of ftp_base_path
    ftpd_trusted_conf_path: str = "/ftpshared/ftpd_trusted.conf"

    # Private FTP users — admin-provisioned R/W accounts, each chrooted to its own
    # folder under a SEPARATE base path from trusted users. Home folders are
    # created by the backend (mode 750) owned ftp_uid:private_ftp_gid.
    private_ftp_base_path: str = "/srv/private_ftp"
    private_ftp_base_mount: str = "/privateftp"   # container-side mount of private_ftp_base_path
    ftpd_private_conf_path: str = "/ftpshared/ftpd_private.conf"
    # Must be a dedicated host group (name + GID) used by nothing else: ProFTPd
    # chroots members of this group to their home via `DefaultRoot ~ <group>`.
    private_ftp_gid: int = 986
    private_ftp_group: str = "privateftp"

    @field_validator("private_ftp_group")
    @classmethod
    def _safe_private_group(cls, v: str) -> str:
        # Written verbatim into ftpd_private.conf.
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", v):
            raise ValueError("PRIVATE_FTP_GROUP must be a valid Unix group name")
        return v

    # FTP ban system DB, owned by the host-side ciosuseradd-ftpban daemon
    ftpban_db_path: str = "/ftpban/ftpban.db"

    # Live-sessions snapshot written by the host-side ftpwho exporter
    ftpwho_json_path: str = "/ftpwho/ftpwho.json"

    # nginx .htpasswd file
    htpasswd_path: str = "/httpshared/.htpasswd"

    # Branding / public-facing details shown in the UI (served via GET /public/site)
    site_name: str = "FTP User Manager"
    ftp_public_host: str = ""

    # Shared public HTTP basic-auth login (the preserved first line of
    # .htpasswd). Its downloads land in user_downloads but are counted as
    # anonymous everywhere — see _registered_downloads_sql() in logs.py.
    public_http_username: str = "public"

    # "Wrong login page?" pointer shown on the admin login page's ban/warning
    # messages, for visitors who meant to reach a different site. Empty = hidden.
    wrong_portal_name: str = ""
    wrong_portal_url: str = ""

    @field_validator("wrong_portal_url")
    @classmethod
    def _safe_portal_url(cls, v: str) -> str:
        v = v.strip()
        if v and not re.fullmatch(r"https?://[^\s\"'<>]+", v):
            raise ValueError("WRONG_PORTAL_URL must be an http(s):// URL")
        return v

    @field_validator("public_http_username")
    @classmethod
    def _safe_public_user(cls, v: str) -> str:
        # Embedded directly into SQL fragments in logs.py — keep it strict.
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", v):
            raise ValueError("PUBLIC_HTTP_USERNAME must match [A-Za-z0-9_.-]{1,64}")
        return v

    # CORS — comma-separated list or bare *
    allowed_origins_str: str = "*"

    @property
    def allowed_origins(self) -> List[str]:
        if self.allowed_origins_str.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.allowed_origins_str.split(",") if o.strip()]

    class Config:
        env_file = ".env"


settings = Settings()
