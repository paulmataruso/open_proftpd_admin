import ipaddress
import re
from datetime import datetime
from uuid import UUID
from typing import Optional, List, Any
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from config import settings

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,32}$')
PASSWORD_MIN = 8

RESERVED_USERNAMES = {
    # System accounts
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
    "nobody", "systemd", "syslog", "messagebus", "uuidd", "dnsmasq",
    "usbmux", "rtkit", "cups", "avahi", "speech", "pulse", "saned",
    "colord", "hplip", "geoclue", "gnome", "gdm", "sshd", "ntp",
    "ubuntu", "debian", "centos", "fedora",
    # FTP / SFTP accounts
    "ftp", "anonftp", "anonymous", "ftpuser", "ftpadmin", "ftproot",
    "sftp", "sftpadmin", "sftpuser", "sftproot",
    # Server software
    "www", "nginx", "apache", "mysql", "postgres",
    "postgresql", "redis", "mongodb", "docker", "git", "svn",
    "nagios", "zabbix", "monitor", "monitoring",
    "deploy", "deployer", "pipeline", "ci", "cicd",
    # Administrative roles
    "admin", "administrator", "superuser", "su", "operator",
    "postmaster", "webmaster", "hostmaster", "abuse", "noc",
    "security", "support", "info", "contact", "help",
    # Generic / test accounts
    "test", "tester", "testing", "guest", "demo", "user", "public",
    "temp", "tmp", "new", "sample",
}


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        v = v.lower().strip()
        if not USERNAME_RE.match(v):
            raise ValueError("Username must be 3–32 characters: letters, numbers, underscores only")
        if v in RESERVED_USERNAMES or v == settings.public_http_username.lower():
            raise ValueError("That username is not available")
        reserved_prefixes = ("root", "admin", "sys", "ftp", "sftp", "www")
        if any(v.startswith(p) for p in reserved_prefixes):
            raise ValueError("That username is not available")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < PASSWORD_MIN:
            raise ValueError(f"Password must be at least {PASSWORD_MIN} characters")
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v


class AdminCreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        v = v.lower().strip()
        if not USERNAME_RE.match(v):
            raise ValueError("Username must be 3–32 characters: letters, numbers, underscores only")
        if v in RESERVED_USERNAMES or v == settings.public_http_username.lower():
            raise ValueError("That username is not available")
        reserved_prefixes = ("root", "admin", "sys", "ftp", "sftp", "www")
        if any(v.startswith(p) for p in reserved_prefixes):
            raise ValueError("That username is not available")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < PASSWORD_MIN:
            raise ValueError(f"Password must be at least {PASSWORD_MIN} characters")
        return v


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    enabled: bool
    created_at: datetime
    last_login: Optional[datetime]
    notes: Optional[str]
    registered_from_ip: Optional[str] = None

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int


class UpdateNotesRequest(BaseModel):
    notes: Optional[str] = None


class UpdateEmailRequest(BaseModel):
    email: EmailStr


class ChangePasswordRequest(BaseModel):
    password: str
    confirm_password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < PASSWORD_MIN:
            raise ValueError(f"Password must be at least {PASSWORD_MIN} characters")
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v


class MessageResponse(BaseModel):
    message: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AuditLogEntry(BaseModel):
    id: int
    username: Optional[str]
    action: str
    detail: Optional[str]
    ip_address: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class SyncResponse(BaseModel):
    message: str
    users_written: int


# ── Admin settings schemas ─────────────────────────────────────────────────────

class AdminChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < PASSWORD_MIN:
            raise ValueError(f"Password must be at least {PASSWORD_MIN} characters")
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class AdminChangeUsernameRequest(BaseModel):
    new_username: str

    @field_validator("new_username")
    @classmethod
    def validate(cls, v):
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        return v


class LogSettingsRequest(BaseModel):
    log_filename: Optional[str] = None
    log_retention_days: Optional[int] = None
    log_retention_enabled: Optional[bool] = None
    http_log_filename: Optional[str] = None
    http_log_enabled: Optional[bool] = None

    @field_validator("log_filename", "http_log_filename")
    @classmethod
    def validate_filename(cls, v):
        if v is not None:
            v = v.strip()
            if "/" in v or "\\" in v or ".." in v:
                raise ValueError("Filename must not contain path separators")
            if not v.endswith(".log"):
                raise ValueError("Filename must end in .log")
        return v

    @field_validator("log_retention_days")
    @classmethod
    def validate_retention(cls, v):
        if v is not None and (v < 1 or v > 3650):
            raise ValueError("Retention must be between 1 and 3650 days")
        return v


class SystemSettingsResponse(BaseModel):
    admin_username: str
    log_filename: str
    log_retention_days: int
    log_retention_enabled: bool
    http_log_filename: str
    http_log_enabled: bool
    tailer_status: str
    tailer_last_write: str
    tailer_pos: int
    tailer_total_rows: int


# ── FTP Activity Log Schemas ───────────────────────────────────────────────────

class UserDownloadRow(BaseModel):
    id: int
    logged_at: str
    ip_address: str
    username: str
    filepath: str
    filename: str
    bytes: Optional[int]
    source: str = "ftp"


class AnonDownloadRow(BaseModel):
    id: int
    logged_at: str
    ip_address: str
    filepath: str
    filename: str
    bytes: Optional[int]
    source: str = "ftp"


class UserDownloadPage(BaseModel):
    total: int
    page: int
    limit: int
    pages: int
    rows: List[UserDownloadRow]


class AnonDownloadPage(BaseModel):
    total: int
    page: int
    limit: int
    pages: int
    rows: List[AnonDownloadRow]


class UserDownloadStats(BaseModel):
    total: int
    unique_users: int
    unique_ips: int
    unique_files: int
    total_bytes: int
    top_files: List[Any]
    top_users: List[Any]
    top_ips: List[Any]


class AnonDownloadStats(BaseModel):
    total: int
    unique_ips: int
    unique_files: int
    total_bytes: int
    top_files: List[Any]
    top_ips: List[Any]


class TimelineBucket(BaseModel):
    bucket: str
    downloads: int
    bytes: int


class SummaryMetric(BaseModel):
    current: int
    previous: int
    change: Optional[float]


class SummaryTimelineBucket(BaseModel):
    bucket: str
    user_downloads: int
    anon_downloads: int
    bytes: int


class SummaryResponse(BaseModel):
    days: int
    user_downloads: SummaryMetric
    user_bytes: SummaryMetric
    anon_downloads: SummaryMetric
    anon_bytes: SummaryMetric
    timeline: List[SummaryTimelineBucket]


class UserBreakdownRow(BaseModel):
    username: str
    downloads: int
    bytes: int


# ── FTP Upload Schemas ─────────────────────────────────────────────────────────

class UserUploadRow(BaseModel):
    id: int
    logged_at: str
    ip_address: str
    username: str
    filepath: str
    filename: str
    bytes: Optional[int]
    source: str = "ftp"


class AnonUploadRow(BaseModel):
    id: int
    logged_at: str
    ip_address: str
    filepath: str
    filename: str
    bytes: Optional[int]
    source: str = "ftp"


class UserUploadPage(BaseModel):
    total: int
    page: int
    limit: int
    pages: int
    rows: List[UserUploadRow]


class AnonUploadPage(BaseModel):
    total: int
    page: int
    limit: int
    pages: int
    rows: List[AnonUploadRow]


class UserUploadStats(BaseModel):
    total: int
    unique_users: int
    unique_ips: int
    unique_files: int
    total_bytes: int
    top_files: List[Any]
    top_users: List[Any]
    top_ips: List[Any]


class AnonUploadStats(BaseModel):
    total: int
    unique_ips: int
    unique_files: int
    total_bytes: int
    top_files: List[Any]
    top_ips: List[Any]


# ── Trusted FTP User Schemas ───────────────────────────────────────────────────

_FTP_HOME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._\-/]*$')


def _clean_ftp_home(v: str) -> str:
    v = v.strip().strip('/')
    if not v:
        raise ValueError("FTP home directory is required")
    parts = v.split('/')
    if '..' in parts or '.' in parts:
        raise ValueError("FTP home directory cannot contain path traversal components")
    if '//' in v:
        raise ValueError("FTP home directory cannot contain consecutive slashes")
    if not _FTP_HOME_RE.match(v):
        raise ValueError("FTP home dir: only letters, numbers, hyphens, underscores, dots, and slashes")
    return v


class TrustedUserCreateRequest(BaseModel):
    username: str
    password: str
    ftp_home_dir: str
    notes: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        v = v.lower().strip()
        if not USERNAME_RE.match(v):
            raise ValueError("Username must be 3–32 characters: letters, numbers, underscores only")
        if v in RESERVED_USERNAMES or v == settings.public_http_username.lower():
            raise ValueError("That username is not available")
        reserved_prefixes = ("root", "admin", "sys", "ftp", "sftp", "www")
        if any(v.startswith(p) for p in reserved_prefixes):
            raise ValueError("That username is not available")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < PASSWORD_MIN:
            raise ValueError(f"Password must be at least {PASSWORD_MIN} characters")
        return v

    @field_validator("ftp_home_dir")
    @classmethod
    def validate_ftp_home(cls, v):
        return _clean_ftp_home(v)


class TrustedUserResponse(BaseModel):
    id: UUID
    username: str
    ftp_home_dir: str
    enabled: bool
    created_at: datetime
    notes: Optional[str]

    class Config:
        from_attributes = True


class TrustedUserListResponse(BaseModel):
    users: List[TrustedUserResponse]
    total: int


class TrustedUserUpdateNotesRequest(BaseModel):
    notes: Optional[str] = None


class PrivateUserCreateRequest(TrustedUserCreateRequest):
    # Optional for private users — defaults to the username.
    ftp_home_dir: Optional[str] = None

    @field_validator("ftp_home_dir")
    @classmethod
    def validate_ftp_home(cls, v):
        if v is None or not v.strip().strip('/'):
            return None
        return _clean_ftp_home(v)

    @model_validator(mode="after")
    def default_home(self):
        if not self.ftp_home_dir:
            self.ftp_home_dir = self.username
        return self


PrivateUserResponse = TrustedUserResponse
class PrivateUserListResponse(TrustedUserListResponse):
    base_path: str
PrivateUserUpdateNotesRequest = TrustedUserUpdateNotesRequest


# ── FTP ban system (see ftpban.py / host daemon ftpban/ftpban.py) ──────────────

_ANON_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


class FtpBanRule(BaseModel):
    enabled: bool
    count: int = Field(ge=1, le=100000)
    window_min: int = Field(ge=1, le=10080)
    ban_min: int = Field(ge=1, le=525600)


class FtpBanRules(BaseModel):
    notransfer: FtpBanRule
    idle: FtpBanRule
    connect: FtpBanRule
    aborted: FtpBanRule


class FtpBanEscalation(BaseModel):
    enabled: bool
    multiplier: float = Field(ge=1, le=10)
    lookback_days: int = Field(ge=1, le=365)
    max_ban_hours: int = Field(ge=1, le=87600)


class FtpBanMessages(BaseModel):
    notransfer: str = Field(min_length=1, max_length=300)
    idle: str = Field(min_length=1, max_length=300)
    connect: str = Field(min_length=1, max_length=300)
    aborted: str = Field(min_length=1, max_length=300)
    manual: str = Field(min_length=1, max_length=300)

    @field_validator("*")
    @classmethod
    def _one_line(cls, v):
        v = re.sub(r"\s+", " ", v).strip()
        if not v:
            raise ValueError("Message can't be empty")
        return v


class FtpBanSettings(BaseModel):
    enforce: bool
    anon_users: List[str] = Field(min_length=1, max_length=20)
    rules: FtpBanRules
    escalation: FtpBanEscalation
    # Managed via /admin/ftpban/whitelist; ignored here so a stale Settings form can't clobber it.
    whitelist: Optional[List[str]] = None
    ports: str
    control_port: int = Field(ge=1, le=65535)
    responder_port: int = Field(ge=1024, le=65535)
    retention_days: int = Field(ge=1, le=3650)
    messages: FtpBanMessages

    @model_validator(mode="after")
    def _port_clash(self):
        if self.responder_port == self.control_port:
            raise ValueError("Responder port must differ from the FTP control port")
        for part in self.ports.split(","):
            lo, _, hi = part.partition("-")
            if int(lo) <= self.responder_port <= int(hi or lo):
                raise ValueError("Responder port must not be inside the blocked ports")
        return self

    @field_validator("anon_users")
    @classmethod
    def _anon_users(cls, v):
        v = [u.strip() for u in v if u.strip()]
        if not v or not all(_ANON_USER_RE.match(u) for u in v):
            raise ValueError("Anonymous usernames: letters, numbers, . _ - only")
        return v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v):
        v = re.sub(r"\s+", "", v)
        if not _PORTS_RE.match(v):
            raise ValueError("Ports: comma-separated ports or ranges, e.g. 21,15000-30000")
        for part in v.split(","):
            lo, _, hi = part.partition("-")
            lo, hi = int(lo), int(hi or lo)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"Ports: '{part}' is out of range")
        return v


class FtpBanManualRequest(BaseModel):
    ip: str
    duration_minutes: Optional[int] = Field(default=None, ge=1, le=525600)  # None = permanent
    reason: Optional[str] = Field(default=None, max_length=300)

    @field_validator("ip")
    @classmethod
    def _ip(cls, v):
        try:
            return ipaddress.ip_address(v.strip()).compressed
        except ValueError:
            raise ValueError("Not a valid IPv4/IPv6 address")


class FtpBanExpiryRequest(BaseModel):
    duration_minutes: Optional[int] = Field(default=None, ge=1, le=525600)  # None = permanent, from now
    enforce: Optional[bool] = None   # True = turn a dry-run entry into a real ban


class FtpBanUnbanIPRequest(BaseModel):
    ip: str


# ── Security Threat Schemas ────────────────────────────────────────────────────

class ThreatEntry(BaseModel):
    id: int
    ip_address: str
    username_attempted: Optional[str]
    matched_user_id: Optional[UUID]
    warning_sent_at: datetime
    escalated_at: Optional[datetime]
    account_disabled: bool
    reviewed: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatListResponse(BaseModel):
    threats: List[ThreatEntry]
    total: int


# ── Ban Schemas ────────────────────────────────────────────────────────────────

class BannedIPEntry(BaseModel):
    id: int
    ip_address: str
    reason: Optional[str]
    banned_by: str
    notes: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class BannedIPListResponse(BaseModel):
    bans: List[BannedIPEntry]
    total: int


class BannedUsernameEntry(BaseModel):
    id: int
    username: str
    reason: Optional[str]
    banned_by: str
    notes: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class BannedUsernameListResponse(BaseModel):
    bans: List[BannedUsernameEntry]
    total: int


class ManualBanIPRequest(BaseModel):
    ip_address: str
    notes: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v):
        import ipaddress
        v = v.strip()
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address")
        return v


def normalize_ip_or_cidr(v: str) -> str:
    """'1.2.3.4' / '1.2.3.0/24' / '2001:db8::/32' -> canonical form; single hosts stay bare IPs."""
    try:
        net = ipaddress.ip_network(v.strip(), strict=False)
    except ValueError:
        raise ValueError("Not a valid IP address or CIDR range")
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else net.compressed


class WhitelistIPRequest(BaseModel):
    cidr: str
    notes: Optional[str] = Field(default=None, max_length=300)

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v):
        return normalize_ip_or_cidr(v)


class WhitelistIPEntry(BaseModel):
    id: int
    cidr: str
    notes: Optional[str]
    created_by: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class WhitelistIPListResponse(BaseModel):
    entries: List[WhitelistIPEntry]
    total: int
    your_ip: str


class ManualBanUsernameRequest(BaseModel):
    username: str
    notes: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError("Username must be 1–64 characters")
        return v


class MultiAccountEntry(BaseModel):
    ip_address: str
    username_count: int
    usernames: List[str]
    last_seen: Optional[datetime]


class MultiAccountListResponse(BaseModel):
    entries: List[MultiAccountEntry]
    total: int
