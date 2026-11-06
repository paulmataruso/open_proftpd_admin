import asyncio
import ipaddress
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import engine, get_db, Base, SessionLocal
from models import User, AuditLog, TrustedFtpUser, PrivateFtpUser, AdminIntrusionAttempt, BannedIP, BannedUsername, WhitelistedIP
from schemas import (
    RegisterRequest, AdminLoginRequest, AdminCreateUserRequest,
    UserResponse, UserListResponse,
    UpdateNotesRequest, UpdateEmailRequest, ChangePasswordRequest,
    AdminChangePasswordRequest, AdminChangeUsernameRequest,
    LogSettingsRequest, SystemSettingsResponse,
    MessageResponse, TokenResponse, AuditLogEntry, SyncResponse,
    UserDownloadPage, AnonDownloadPage,
    UserDownloadStats, AnonDownloadStats, SummaryResponse,
    UserUploadPage, AnonUploadPage, UserUploadStats, AnonUploadStats,
    TrustedUserCreateRequest, TrustedUserResponse, TrustedUserListResponse,
    TrustedUserUpdateNotesRequest,
    PrivateUserCreateRequest, PrivateUserResponse, PrivateUserListResponse,
    PrivateUserUpdateNotesRequest,
    ThreatEntry, ThreatListResponse,
    BannedIPEntry, BannedIPListResponse,
    BannedUsernameEntry, BannedUsernameListResponse,
    ManualBanIPRequest, ManualBanUsernameRequest,
    MultiAccountEntry, MultiAccountListResponse,
    FtpBanSettings, FtpBanManualRequest, FtpBanExpiryRequest, FtpBanUnbanIPRequest,
    WhitelistIPRequest, WhitelistIPEntry, WhitelistIPListResponse,
)
from auth import (
    hash_password, verify_admin, create_access_token, verify_token,
    seed_admin_config, change_admin_password, change_admin_username,
    get_admin_username,
)
from ftpfile import regenerate_ftpd_passwd, regenerate_ftpd_trusted_conf, regenerate_ftpd_private_conf
from httpfile import regenerate_htpasswd
from config import settings
import logs as ftplogs
import ftpban

logger = logging.getLogger("uvicorn.error")


# ── Startup / shutdown ────────────────────────────────────────────────────────

def validate_config():
    if len(settings.secret_key) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters.")
    passwd_dir = os.path.dirname(settings.ftpd_passwd_path)
    if not os.path.isdir(passwd_dir):
        raise RuntimeError(f"FTPD_PASSWD_PATH directory does not exist: {passwd_dir}")
    trusted_dir = os.path.dirname(settings.ftpd_trusted_conf_path)
    if not os.path.isdir(trusted_dir):
        raise RuntimeError(f"FTPD_TRUSTED_CONF_PATH directory does not exist: {trusted_dir}")
    private_dir = os.path.dirname(settings.ftpd_private_conf_path)
    if not os.path.isdir(private_dir):
        raise RuntimeError(f"FTPD_PRIVATE_CONF_PATH directory does not exist: {private_dir}")
    htpasswd_dir = os.path.dirname(settings.htpasswd_path)
    if not os.path.isdir(htpasswd_dir):
        raise RuntimeError(f"HTPASSWD_PATH directory does not exist: {htpasswd_dir}")


async def _daily_prune():
    """Background task — prunes old log records once per day."""
    while True:
        await asyncio.sleep(86400)
        try:
            ud, ad = ftplogs.prune_old_records()
            logger.info(f"Log retention pruning: removed {ud} user + {ad} anon rows")
        except Exception as e:
            logger.error(f"Log retention pruning failed: {e}")


async def _stats_cache_warmup():
    """Background task — fills any never-computed stats cache keys on startup.

    Runs once. Keys people actually view are kept fresh by stale-while-
    revalidate on read (logs._swr); a periodic re-warm of every key used to
    recompute ~80 multi-million-row aggregates every 4.5 minutes whether or
    not anyone was looking, which pinned db_logs at 100%+ CPU.
    """
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, ftplogs.warmup_stats_cache)
        logger.info("Stats cache warmed on startup")
    except Exception as e:
        logger.error(f"Initial stats cache warmup failed: {e}")


def _run_migrations():
    """Add columns that SQLAlchemy create_all won't add to existing tables."""
    try:
        with engine.connect() as conn:
            conn.execute(text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS registered_from_ip VARCHAR(45)"
            ))
            conn.commit()
    except Exception as e:
        logger.warning(f"Column migration skipped: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_config()
    Base.metadata.create_all(bind=engine)
    _run_migrations()
    # Seed admin credentials from env on first start
    db = SessionLocal()
    try:
        seed_admin_config(db)
        try:
            publish_activity_users(db)
        except Exception as e:
            logger.error(f"activity user publish failed at startup: {e}")
    finally:
        db.close()
    # Start background tasks
    task = asyncio.create_task(_daily_prune())
    cache_task = asyncio.create_task(_stats_cache_warmup())
    yield
    task.cancel()
    cache_task.cancel()


# ── App setup ─────────────────────────────────────────────────────────────────

def get_real_ip(request: Request) -> str:
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=get_real_ip)

app = FastAPI(
    title="FTP User Manager",
    lifespan=lifespan,
    docs_url=None, redoc_url=None, openapi_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=False,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/login", auto_error=False)


def get_current_admin(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    sub = verify_token(token)
    if not sub or sub != "admin":
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return sub


def audit(db: Session, username: Optional[str], action: str,
          detail: Optional[str] = None, ip: Optional[str] = None):
    db.add(AuditLog(username=username, action=action, detail=detail, ip_address=ip))
    db.commit()


def get_user_or_404(user_id: str, db: Session) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def ftp_username_taken(db: Session, username: str) -> bool:
    """ftpd.passwd is shared by every FTP user class and mod_auth_file uses the first
    matching line, so a username must be unique across all of them."""
    return any(
        db.query(model).filter(model.username == username).first()
        for model in (User, TrustedFtpUser, PrivateFtpUser)
    )


def ip_whitelisted(db: Session, ip: str) -> bool:
    """True if ip falls in the threat whitelist (exempt from intrusion detection + IP bans)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for (cidr,) in db.query(WhitelistedIP.cidr).all():
        try:
            n = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if a.version == n.version and a in n:
            return True
    return False


def publish_activity_users(db: Session):
    """Tell the logtailer whose file activity to record (trusted + private users)."""
    users = [(u, "trusted") for (u,) in db.query(TrustedFtpUser.username).all()]
    users += [(u, "private") for (u,) in db.query(PrivateFtpUser.username).all()]
    ftplogs.set_activity_users(users)


def sync(db: Session):
    try:
        publish_activity_users(db)
    except Exception as e:
        logger.error(f"activity user publish failed: {e}")
    try:
        regenerate_ftpd_passwd(db)
    except Exception as e:
        logger.error(f"ftpd.passwd regeneration failed: {e}")
    try:
        regenerate_ftpd_trusted_conf(db)
    except Exception as e:
        logger.error(f"ftpd_trusted.conf regeneration failed: {e}")
    try:
        regenerate_ftpd_private_conf(db)
    except Exception as e:
        logger.error(f"ftpd_private.conf regeneration failed: {e}")
    try:
        regenerate_htpasswd(db)
    except Exception as e:
        logger.error(f".htpasswd regeneration failed: {e}")


def _logs_err(e: Exception):
    logger.error(f"Activity log database error: {e}")
    raise HTTPException(status_code=503, detail="Activity log database temporarily unavailable")


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


# ── Public registration ───────────────────────────────────────────────────────

@app.post("/register", response_model=MessageResponse, status_code=201)
@limiter.limit("5/minute")
def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)):
    ip = get_real_ip(request)
    if body.username.lower() == get_admin_username(db).lower():
        audit(db, body.username, "register_fail", "username taken", ip)
        raise HTTPException(status_code=409, detail="Username already taken")
    if ftp_username_taken(db, body.username):
        audit(db, body.username, "register_fail", "username taken", ip)
        raise HTTPException(status_code=409, detail="Username already taken")
    if db.query(User).filter(User.email == body.email).first():
        audit(db, body.username, "register_fail", "email taken", ip)
        raise HTTPException(status_code=409, detail="Username already taken")
    if ip and ip != "unknown":
        existing_ip = db.query(User).filter(User.registered_from_ip == ip).first()
        if existing_ip:
            audit(db, body.username, "register_fail", f"duplicate IP {ip}", ip)
            raise HTTPException(
                status_code=409,
                detail="An account already exists from your IP address. Each IP address is limited to one account.",
            )
    user = User(
        username=body.username, email=body.email,
        password_hash=hash_password(body.password), enabled=True,
        registered_from_ip=ip if ip != "unknown" else None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    sync(db)
    audit(db, body.username, "register", "account created", ip)
    return {"message": "Account created successfully. You can now log in to the FTP server."}


# ── Admin auth ────────────────────────────────────────────────────────────────

@app.post("/admin/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def admin_login(request: Request, body: AdminLoginRequest, db: Session = Depends(get_db)):
    from datetime import datetime, timezone as tz
    ip = get_real_ip(request)
    trusted_ip = ip_whitelisted(db, ip)

    # Reject banned IPs immediately (the whitelist overrides IP bans)
    if not trusted_ip and db.query(BannedIP).filter(BannedIP.ip_address == ip).first():
        audit(db, body.username[:64], "admin_login_blocked", f"banned IP {ip}", ip)
        raise HTTPException(status_code=403, detail="blocked")

    # Reject banned usernames — and also ban the new IP if it's not already banned
    if db.query(BannedUsername).filter(BannedUsername.username == body.username).first():
        if ip and ip != "unknown" and not trusted_ip:
            if not db.query(BannedIP).filter(BannedIP.ip_address == ip).first():
                db.add(BannedIP(
                    ip_address=ip,
                    reason=f"attempted login with banned username '{body.username[:64]}'",
                    banned_by="auto",
                ))
                db.commit()
                audit(db, body.username[:64], "ip_auto_banned",
                      f"IP {ip} used banned username '{body.username[:64]}'", ip)
        raise HTTPException(status_code=403, detail="blocked")

    if not verify_admin(body.username, body.password, db):
        audit(db, body.username[:64], "admin_login_fail", "whitelisted IP" if trusted_ip else None, ip)
        secrets.token_bytes(32)
        if trusted_ip:
            # Whitelisted: no intrusion warning, escalation, lockout or auto bans.
            raise HTTPException(status_code=401, detail="Invalid credentials")
        existing = db.query(AdminIntrusionAttempt).filter(
            AdminIntrusionAttempt.ip_address == ip,
            AdminIntrusionAttempt.escalated_at.is_(None),
        ).first()
        if existing is None:
            matched_user = db.query(User).filter(User.username == body.username).first()
            db.add(AdminIntrusionAttempt(
                ip_address=ip,
                username_attempted=body.username[:64],
                matched_user_id=matched_user.id if matched_user else None,
            ))
            db.commit()
            audit(db, body.username[:64], "admin_intrusion_warning",
                  f"first attempt from {ip}", ip)
            raise HTTPException(status_code=403, detail="first_warning")
        else:
            existing.escalated_at = datetime.now(tz.utc)
            matched_user = None
            if existing.matched_user_id:
                matched_user = db.query(User).filter(User.id == existing.matched_user_id).first()
            if not matched_user:
                matched_user = db.query(User).filter(User.username == body.username).first()
                if matched_user:
                    existing.matched_user_id = matched_user.id
            if matched_user and matched_user.enabled:
                matched_user.enabled = False
                existing.account_disabled = True
                db.commit()
                sync(db)
                audit(db, matched_user.username, "admin_intrusion_lockout",
                      f"account disabled — repeated admin portal intrusion from {ip}", ip)
            else:
                db.commit()
                audit(db, body.username[:64], "admin_intrusion_lockout",
                      f"escalated — repeated admin portal intrusion from {ip}", ip)
            # Auto-ban the IP
            if ip and ip != "unknown":
                if not db.query(BannedIP).filter(BannedIP.ip_address == ip).first():
                    db.add(BannedIP(
                        ip_address=ip,
                        reason=f"repeated admin login attempts (username: '{body.username[:64]}')",
                        banned_by="auto",
                    ))
                    db.commit()
                    audit(db, body.username[:64], "ip_auto_banned",
                          f"IP {ip} auto-banned after repeated admin intrusion", ip)
            # Auto-ban the username
            if body.username and not db.query(BannedUsername).filter(
                BannedUsername.username == body.username
            ).first():
                db.add(BannedUsername(
                    username=body.username[:64],
                    reason=f"repeated admin login attempts from {ip}",
                    banned_by="auto",
                ))
                db.commit()
                audit(db, body.username[:64], "username_auto_banned",
                      f"username '{body.username[:64]}' auto-banned after repeated admin intrusion from {ip}", ip)
            raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": "admin"})
    audit(db, body.username, "admin_login", None, ip)
    return {"access_token": token}


# ── Admin — user management ───────────────────────────────────────────────────

@app.get("/admin/stats")
def get_stats(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    total    = db.query(func.count(User.id)).scalar()
    enabled  = db.query(func.count(User.id)).filter(User.enabled == True).scalar()
    disabled = db.query(func.count(User.id)).filter(User.enabled == False).scalar()
    trusted_total   = db.query(func.count(TrustedFtpUser.id)).scalar()
    trusted_enabled = db.query(func.count(TrustedFtpUser.id)).filter(TrustedFtpUser.enabled == True).scalar()
    private_total   = db.query(func.count(PrivateFtpUser.id)).scalar()
    private_enabled = db.query(func.count(PrivateFtpUser.id)).filter(PrivateFtpUser.enabled == True).scalar()
    unreviewed_threats = db.query(func.count(AdminIntrusionAttempt.id)).filter(
        AdminIntrusionAttempt.reviewed == False
    ).scalar()
    return {
        "total": total, "enabled": enabled, "disabled": disabled,
        "trusted_total": trusted_total, "trusted_enabled": trusted_enabled,
        "private_total": private_total, "private_enabled": private_enabled,
        "unreviewed_threats": unreviewed_threats,
    }


@app.post("/admin/sync", response_model=SyncResponse)
def force_sync(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    count = regenerate_ftpd_passwd(db)
    try:
        publish_activity_users(db)
    except Exception as e:
        logger.error(f"activity user publish failed: {e}")
    try:
        regenerate_ftpd_trusted_conf(db)
    except Exception as e:
        logger.error(f"ftpd_trusted.conf sync failed: {e}")
    try:
        regenerate_ftpd_private_conf(db)
    except Exception as e:
        logger.error(f"ftpd_private.conf sync failed: {e}")
    try:
        regenerate_htpasswd(db)
    except Exception as e:
        logger.error(f".htpasswd sync failed: {e}")
    audit(db, "admin", "manual_sync", f"{count} users written")
    return {"message": "ftpd.passwd, ftpd_trusted.conf, ftpd_private.conf, and .htpasswd regenerated", "users_written": count}


@app.get("/admin/audit", response_model=list[AuditLogEntry])
def get_audit_log(
    limit: int = 200, db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    limit = min(limit, 500)
    return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()


# ── Admin — security threats ───────────────────────────────────────────────────

@app.get("/admin/threats", response_model=ThreatListResponse)
def list_threats(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    threats = db.query(AdminIntrusionAttempt).order_by(
        AdminIntrusionAttempt.created_at.desc()
    ).all()
    return {"threats": threats, "total": len(threats)}


@app.put("/admin/threats/{threat_id}/review", response_model=MessageResponse)
def review_threat(
    threat_id: int, db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    threat = db.query(AdminIntrusionAttempt).filter(
        AdminIntrusionAttempt.id == threat_id
    ).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat record not found")
    threat.reviewed = True
    db.commit()
    audit(db, "admin", "threat_reviewed", f"id={threat_id} ip={threat.ip_address}")
    return {"message": "Threat marked as reviewed"}


@app.put("/admin/threats/{threat_id}/reenable", response_model=MessageResponse)
def reenable_threat_user(
    threat_id: int, db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    threat = db.query(AdminIntrusionAttempt).filter(
        AdminIntrusionAttempt.id == threat_id
    ).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat record not found")
    if not threat.matched_user_id:
        raise HTTPException(status_code=400, detail="No user account linked to this threat")
    user = db.query(User).filter(User.id == threat.matched_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found or was deleted")
    user.enabled = True
    threat.reviewed = True
    db.commit()
    sync(db)
    audit(db, user.username, "threat_reenable",
          f"re-enabled after threat review, id={threat_id}")
    return {"message": f"User {user.username} re-enabled and threat marked as reviewed"}


# ── Admin — ban management ─────────────────────────────────────────────────────

@app.get("/admin/bans/ips", response_model=BannedIPListResponse)
def list_banned_ips(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    bans = db.query(BannedIP).order_by(BannedIP.created_at.desc()).all()
    return {"bans": bans, "total": len(bans)}


@app.post("/admin/bans/ips", response_model=MessageResponse, status_code=201)
def ban_ip(
    body: ManualBanIPRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    if db.query(BannedIP).filter(BannedIP.ip_address == body.ip_address).first():
        raise HTTPException(status_code=409, detail="IP address is already banned")
    if ip_whitelisted(db, body.ip_address):
        raise HTTPException(status_code=409, detail="IP address is whitelisted — remove it from the whitelist first")
    db.add(BannedIP(
        ip_address=body.ip_address,
        reason="manually banned by admin",
        banned_by="admin",
        notes=body.notes,
    ))
    db.commit()
    audit(db, "admin", "ip_banned", f"IP {body.ip_address} banned manually",
          get_real_ip(request))
    return {"message": f"IP {body.ip_address} has been banned"}


@app.delete("/admin/bans/ips/{ban_id}", response_model=MessageResponse)
def unban_ip(
    ban_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    ban = db.query(BannedIP).filter(BannedIP.id == ban_id).first()
    if not ban:
        raise HTTPException(status_code=404, detail="Ban not found")
    ip = ban.ip_address
    db.delete(ban)
    db.commit()
    audit(db, "admin", "ip_unbanned", f"IP {ip} unbanned", get_real_ip(request))
    return {"message": f"IP {ip} has been unbanned"}


@app.get("/admin/bans/usernames", response_model=BannedUsernameListResponse)
def list_banned_usernames(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    bans = db.query(BannedUsername).order_by(BannedUsername.created_at.desc()).all()
    return {"bans": bans, "total": len(bans)}


@app.post("/admin/bans/usernames", response_model=MessageResponse, status_code=201)
def ban_username(
    body: ManualBanUsernameRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    if db.query(BannedUsername).filter(BannedUsername.username == body.username).first():
        raise HTTPException(status_code=409, detail="Username is already banned")
    db.add(BannedUsername(
        username=body.username,
        reason="manually banned by admin",
        banned_by="admin",
        notes=body.notes,
    ))
    db.commit()
    audit(db, "admin", "username_banned", f"username '{body.username}' banned manually",
          get_real_ip(request))
    return {"message": f"Username '{body.username}' has been banned"}


@app.delete("/admin/bans/usernames/{ban_id}", response_model=MessageResponse)
def unban_username(
    ban_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    ban = db.query(BannedUsername).filter(BannedUsername.id == ban_id).first()
    if not ban:
        raise HTTPException(status_code=404, detail="Ban not found")
    username = ban.username
    db.delete(ban)
    db.commit()
    audit(db, "admin", "username_unbanned", f"username '{username}' unbanned",
          get_real_ip(request))
    return {"message": f"Username '{username}' has been unbanned"}


@app.get("/admin/whitelist/ips", response_model=WhitelistIPListResponse)
def list_whitelist(request: Request, db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    entries = db.query(WhitelistedIP).order_by(WhitelistedIP.created_at.desc()).all()
    return {"entries": entries, "total": len(entries), "your_ip": get_real_ip(request)}


@app.post("/admin/whitelist/ips", response_model=MessageResponse, status_code=201)
def add_whitelist(
    body: WhitelistIPRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    if db.query(WhitelistedIP).filter(WhitelistedIP.cidr == body.cidr).first():
        raise HTTPException(status_code=409, detail=f"{body.cidr} is already whitelisted")
    by = get_admin_username(db)
    db.add(WhitelistedIP(cidr=body.cidr, notes=(body.notes or "").strip() or None, created_by=by))
    # Existing IP bans inside the range would be dead weight (the whitelist overrides them).
    net = ipaddress.ip_network(body.cidr, strict=False)
    lifted = []
    for ban in db.query(BannedIP).all():
        try:
            a = ipaddress.ip_address(ban.ip_address)
        except ValueError:
            continue
        if a.version == net.version and a in net:
            lifted.append(ban.ip_address)
            db.delete(ban)
    db.commit()
    audit(db, by, "ip_whitelisted",
          f"{body.cidr}" + (f" (lifted bans: {', '.join(lifted)})" if lifted else ""), get_real_ip(request))
    msg = f"{body.cidr} whitelisted"
    if lifted:
        msg += f" — removed {len(lifted)} IP ban{'s' if len(lifted) != 1 else ''}"
    return {"message": msg}


@app.delete("/admin/whitelist/ips/{entry_id}", response_model=MessageResponse)
def remove_whitelist(
    entry_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    entry = db.query(WhitelistedIP).filter(WhitelistedIP.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Whitelist entry not found")
    cidr = entry.cidr
    db.delete(entry)
    db.commit()
    audit(db, get_admin_username(db), "ip_unwhitelisted", cidr, get_real_ip(request))
    return {"message": f"{cidr} removed from the whitelist"}


@app.get("/admin/bans/multi-account", response_model=MultiAccountListResponse)
def list_multi_account(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    rows = db.execute(text("""
        SELECT
            ip_address,
            COUNT(DISTINCT username_attempted)::int AS username_count,
            array_agg(DISTINCT username_attempted) AS usernames,
            MAX(created_at) AS last_seen
        FROM admin_intrusion_attempts
        WHERE username_attempted IS NOT NULL
        GROUP BY ip_address
        HAVING COUNT(DISTINCT username_attempted) > 1
        ORDER BY username_count DESC
    """)).fetchall()
    entries = [
        MultiAccountEntry(
            ip_address=row.ip_address,
            username_count=row.username_count,
            usernames=[u for u in (row.usernames or []) if u is not None],
            last_seen=row.last_seen,
        )
        for row in rows
    ]
    return {"entries": entries, "total": len(entries)}


@app.get("/admin/users", response_model=UserListResponse)
def list_users(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return {"users": users, "total": len(users)}


@app.post("/admin/users", response_model=UserResponse, status_code=201)
def admin_create_user(
    body: AdminCreateUserRequest,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    if ftp_username_taken(db, body.username):
        raise HTTPException(status_code=409, detail="Username already taken")
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(
        username=body.username, email=body.email,
        password_hash=hash_password(body.password), enabled=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    sync(db)
    audit(db, body.username, "admin_create", "account created by admin")
    return user


@app.get("/admin/users/export")
def export_users(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    users = db.query(User).order_by(User.created_at).all()
    data = [{
        "id":         str(u.id),
        "username":   u.username,
        "email":      u.email,
        "enabled":    u.enabled,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "notes":      u.notes,
    } for u in users]
    import json
    from fastapi.responses import Response
    payload = json.dumps(
        {"version": 1, "exported_at": __import__('datetime').datetime.utcnow().isoformat(), "users": data},
        indent=2,
    )
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=users_export.json"},
    )


@app.post("/admin/users/import", response_model=MessageResponse)
async def import_users(
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    import json, re
    _BCRYPT_RE = re.compile(r'^\$2[aby]\$\d{2}\$.{53}$')
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    users_data = body.get("users") if isinstance(body, dict) else body
    if not isinstance(users_data, list):
        raise HTTPException(status_code=400, detail="Expected a list of users or {\"users\": [...]}")

    imported = skipped = errors = 0
    for row in users_data:
        try:
            username = str(row.get("username", "")).strip().lower()
            email    = str(row.get("email", "")).strip()
            pw_hash  = str(row.get("password_hash", "")).strip()
            if not username or not email or not pw_hash:
                errors += 1
                continue
            if not _BCRYPT_RE.match(pw_hash):
                errors += 1
                continue
            if db.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first():
                skipped += 1
                continue
            from datetime import datetime, timezone
            def _parse_dt(v):
                if not v: return None
                try: return datetime.fromisoformat(v.replace("Z", "+00:00"))
                except Exception: return None
            user = User(
                username      = username,
                email         = email,
                password_hash = pw_hash,
                enabled       = bool(row.get("enabled", True)),
                notes         = row.get("notes"),
                created_at    = _parse_dt(row.get("created_at")),
                last_login    = _parse_dt(row.get("last_login")),
            )
            db.add(user)
            imported += 1
        except Exception:
            errors += 1
            continue

    db.commit()
    if imported > 0:
        sync(db)
    audit(db, "admin", "user_import",
          f"imported={imported}, skipped={skipped}, errors={errors}",
          get_real_ip(request))
    return {"message": f"Import complete — {imported} imported, {skipped} skipped (already exist), {errors} errors"}


@app.get("/admin/users/{user_id}", response_model=UserResponse)
def get_user(user_id: str, db: Session = Depends(get_db),
             _: str = Depends(get_current_admin)):
    return get_user_or_404(user_id, db)


@app.put("/admin/users/{user_id}/toggle", response_model=MessageResponse)
def toggle_user(user_id: str, db: Session = Depends(get_db),
                _: str = Depends(get_current_admin)):
    user = get_user_or_404(user_id, db)
    user.enabled = not user.enabled
    db.commit()
    sync(db)
    action = "enabled" if user.enabled else "disabled"
    audit(db, user.username, f"admin_{action}", "by admin")
    return {"message": f"User {user.username} {action}"}


@app.put("/admin/users/{user_id}/password", response_model=MessageResponse)
def change_password(
    user_id: str, body: ChangePasswordRequest,
    db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    user = get_user_or_404(user_id, db)
    user.password_hash = hash_password(body.password)
    db.commit()
    sync(db)
    audit(db, user.username, "admin_password_change", "password changed by admin")
    return {"message": f"Password updated for {user.username}"}


@app.put("/admin/users/{user_id}/email", response_model=MessageResponse)
def change_email(
    user_id: str, body: UpdateEmailRequest,
    db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    user = get_user_or_404(user_id, db)
    existing = db.query(User).filter(User.email == body.email,
                                     User.id != user_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already in use")
    old = user.email
    user.email = body.email
    db.commit()
    audit(db, user.username, "admin_email_change", f"{old} → {body.email}")
    return {"message": f"Email updated for {user.username}"}


@app.put("/admin/users/{user_id}/notes", response_model=MessageResponse)
def update_notes(
    user_id: str, body: UpdateNotesRequest,
    db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    user = get_user_or_404(user_id, db)
    user.notes = body.notes
    db.commit()
    return {"message": "Notes updated"}


@app.delete("/admin/users/{user_id}", response_model=MessageResponse)
def delete_user(user_id: str, db: Session = Depends(get_db),
                _: str = Depends(get_current_admin)):
    user = get_user_or_404(user_id, db)
    username = user.username
    db.delete(user)
    db.commit()
    sync(db)
    audit(db, username, "admin_delete", "account deleted by admin")
    return {"message": f"User {username} deleted"}


@app.get("/admin/trusted", response_model=TrustedUserListResponse)
def list_trusted(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    users = db.query(TrustedFtpUser).order_by(TrustedFtpUser.created_at.desc()).all()
    return {"users": users, "total": len(users)}


@app.post("/admin/trusted", response_model=TrustedUserResponse, status_code=201)
def create_trusted(
    body: TrustedUserCreateRequest,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    if ftp_username_taken(db, body.username):
        raise HTTPException(status_code=409, detail="Username already taken")
    user = TrustedFtpUser(
        username=body.username,
        password_hash=hash_password(body.password),
        ftp_home_dir=body.ftp_home_dir,
        notes=body.notes,
        enabled=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    sync(db)
    audit(db, body.username, "trusted_create", f"home={body.ftp_home_dir}")
    return user


def get_trusted_or_404(user_id: str, db: Session) -> TrustedFtpUser:
    user = db.query(TrustedFtpUser).filter(TrustedFtpUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Trusted user not found")
    return user


@app.put("/admin/trusted/{user_id}/toggle", response_model=MessageResponse)
def toggle_trusted(user_id: str, db: Session = Depends(get_db),
                   _: str = Depends(get_current_admin)):
    user = get_trusted_or_404(user_id, db)
    user.enabled = not user.enabled
    db.commit()
    sync(db)
    action = "enabled" if user.enabled else "disabled"
    audit(db, user.username, f"trusted_{action}", "by admin")
    return {"message": f"Trusted user {user.username} {action}"}


@app.put("/admin/trusted/{user_id}/password", response_model=MessageResponse)
def change_trusted_password(
    user_id: str, body: ChangePasswordRequest,
    db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    user = get_trusted_or_404(user_id, db)
    user.password_hash = hash_password(body.password)
    db.commit()
    sync(db)
    audit(db, user.username, "trusted_password_change", "password changed by admin")
    return {"message": f"Password updated for {user.username}"}


@app.put("/admin/trusted/{user_id}/notes", response_model=MessageResponse)
def update_trusted_notes(
    user_id: str, body: TrustedUserUpdateNotesRequest,
    db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    user = get_trusted_or_404(user_id, db)
    user.notes = body.notes
    db.commit()
    return {"message": "Notes updated"}


@app.delete("/admin/trusted/{user_id}", response_model=MessageResponse)
def delete_trusted(user_id: str, db: Session = Depends(get_db),
                   _: str = Depends(get_current_admin)):
    user = get_trusted_or_404(user_id, db)
    username, home = user.username, user.ftp_home_dir
    db.delete(user)
    db.commit()
    sync(db)
    audit(db, username, "trusted_delete", f"home={home}")
    return {"message": f"Trusted user {username} deleted"}


@app.post("/admin/trusted/{user_id}/fix-permissions", response_model=MessageResponse)
def fix_trusted_permissions(
    user_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    user = get_trusted_or_404(user_id, db)
    mount = os.path.realpath(settings.ftp_base_mount)
    full_path = os.path.normpath(os.path.join(mount, user.ftp_home_dir))
    if not full_path.startswith(mount + os.sep) and full_path != mount:
        raise HTTPException(status_code=400, detail="Invalid home directory path")
    if not os.path.isdir(full_path):
        raise HTTPException(
            status_code=404,
            detail=f"Directory not found: {user.ftp_home_dir} — create it on the FTP server first",
        )
    os.chown(full_path, settings.ftp_uid, settings.trusted_ftp_gid)
    os.chmod(full_path, 0o755)
    fixed = 1
    for root, dirs, files in os.walk(full_path):
        for d in dirs:
            p = os.path.join(root, d)
            os.chown(p, settings.ftp_uid, settings.trusted_ftp_gid)
            os.chmod(p, 0o755)
            fixed += 1
        for f in files:
            p = os.path.join(root, f)
            os.chown(p, settings.ftp_uid, settings.trusted_ftp_gid)
            os.chmod(p, 0o644)
            fixed += 1
    audit(db, user.username, "trusted_fix_perms",
          f"chown -R {settings.ftp_uid}:{settings.trusted_ftp_gid} ({fixed} entries) {user.ftp_home_dir}")
    return {"message": f"Permissions fixed on {fixed} item(s) under {user.ftp_home_dir} (uid={settings.ftp_uid} gid={settings.trusted_ftp_gid})"}


# ── Admin — private FTP users ─────────────────────────────────────────────────
# R/W accounts chrooted under PRIVATE_FTP_BASE_PATH — a separate tree from trusted
# users' FTP_BASE_PATH. Unlike trusted users, the home folder is created here.

PRIVATE_DIR_MODE  = 0o750
PRIVATE_FILE_MODE = 0o640


def _private_full_path(user: PrivateFtpUser) -> str:
    mount = os.path.realpath(settings.private_ftp_base_mount)
    full_path = os.path.normpath(os.path.join(mount, user.ftp_home_dir))
    if not full_path.startswith(mount + os.sep):
        raise HTTPException(status_code=400, detail="Invalid home directory path")
    return full_path


def _private_chown(path: str, mode: int) -> None:
    os.chown(path, settings.ftp_uid, settings.private_ftp_gid)
    os.chmod(path, mode)


def get_private_or_404(user_id: str, db: Session) -> PrivateFtpUser:
    user = db.query(PrivateFtpUser).filter(PrivateFtpUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Private user not found")
    return user


@app.get("/admin/private", response_model=PrivateUserListResponse)
def list_private(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    users = db.query(PrivateFtpUser).order_by(PrivateFtpUser.created_at.desc()).all()
    return {"users": users, "total": len(users), "base_path": settings.private_ftp_base_path.rstrip("/")}


@app.post("/admin/private", response_model=PrivateUserResponse, status_code=201)
def create_private(
    body: PrivateUserCreateRequest,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    if ftp_username_taken(db, body.username):
        raise HTTPException(status_code=409, detail="Username already taken")
    if db.query(PrivateFtpUser).filter(PrivateFtpUser.ftp_home_dir == body.ftp_home_dir).first():
        raise HTTPException(status_code=409, detail="That home folder is already assigned to another private user")
    user = PrivateFtpUser(
        username=body.username,
        password_hash=hash_password(body.password),
        ftp_home_dir=body.ftp_home_dir,
        notes=body.notes,
        enabled=True,
    )
    full_path = _private_full_path(user)
    if not os.path.isdir(settings.private_ftp_base_mount):
        raise HTTPException(status_code=500, detail="Private FTP base path is not mounted in the backend")
    try:
        existed = os.path.isdir(full_path)
        os.makedirs(full_path, exist_ok=True)
        _private_chown(full_path, PRIVATE_DIR_MODE)
    except OSError as e:
        logger.error(f"private home create failed for {body.username}: {e}")
        raise HTTPException(status_code=500, detail=f"Could not create home folder: {e.strerror}")
    db.add(user)
    db.commit()
    db.refresh(user)
    sync(db)
    audit(db, body.username, "private_create",
          f"home={body.ftp_home_dir} ({'existing folder' if existed else 'folder created'})")
    return user


@app.put("/admin/private/{user_id}/toggle", response_model=MessageResponse)
def toggle_private(user_id: str, db: Session = Depends(get_db),
                   _: str = Depends(get_current_admin)):
    user = get_private_or_404(user_id, db)
    user.enabled = not user.enabled
    db.commit()
    sync(db)
    action = "enabled" if user.enabled else "disabled"
    audit(db, user.username, f"private_{action}", "by admin")
    return {"message": f"Private user {user.username} {action}"}


@app.put("/admin/private/{user_id}/password", response_model=MessageResponse)
def change_private_password(
    user_id: str, body: ChangePasswordRequest,
    db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    user = get_private_or_404(user_id, db)
    user.password_hash = hash_password(body.password)
    db.commit()
    sync(db)
    audit(db, user.username, "private_password_change", "password changed by admin")
    return {"message": f"Password updated for {user.username}"}


@app.put("/admin/private/{user_id}/notes", response_model=MessageResponse)
def update_private_notes(
    user_id: str, body: PrivateUserUpdateNotesRequest,
    db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    user = get_private_or_404(user_id, db)
    user.notes = body.notes
    db.commit()
    return {"message": "Notes updated"}


@app.delete("/admin/private/{user_id}", response_model=MessageResponse)
def delete_private(user_id: str, db: Session = Depends(get_db),
                   _: str = Depends(get_current_admin)):
    """Removes the account only — the home folder and its files are left on disk."""
    user = get_private_or_404(user_id, db)
    username, home = user.username, user.ftp_home_dir
    db.delete(user)
    db.commit()
    sync(db)
    audit(db, username, "private_delete", f"home={home} (folder kept)")
    return {"message": f"Private user {username} deleted — folder {home} was kept on disk"}


@app.post("/admin/private/{user_id}/fix-permissions", response_model=MessageResponse)
def fix_private_permissions(
    user_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    user = get_private_or_404(user_id, db)
    full_path = _private_full_path(user)
    if not os.path.isdir(full_path):
        raise HTTPException(status_code=404, detail=f"Directory not found: {user.ftp_home_dir}")
    _private_chown(full_path, PRIVATE_DIR_MODE)
    fixed = 1
    for root, dirs, files in os.walk(full_path):
        for d in dirs:
            _private_chown(os.path.join(root, d), PRIVATE_DIR_MODE)
            fixed += 1
        for f in files:
            _private_chown(os.path.join(root, f), PRIVATE_FILE_MODE)
            fixed += 1
    audit(db, user.username, "private_fix_perms",
          f"chown -R {settings.ftp_uid}:{settings.private_ftp_gid} ({fixed} entries) {user.ftp_home_dir}")
    return {"message": f"Permissions fixed on {fixed} item(s) under {user.ftp_home_dir} (uid={settings.ftp_uid} gid={settings.private_ftp_gid})"}


# ── Admin — home folder sizes (trusted + private) ─────────────────────────────
# Fetched separately from the user lists so a slow walk over NFS never delays
# the table. Cached in memory per folder for FOLDER_SIZE_TTL seconds.

FOLDER_SIZE_TTL = 60
_folder_size_cache: dict = {}


def _folder_size(path: str) -> dict:
    import time
    now = time.time()
    hit = _folder_size_cache.get(path)
    if hit and now - hit["at"] < FOLDER_SIZE_TTL:
        return hit["val"]
    if not os.path.isdir(path):
        val = {"exists": False, "bytes": 0, "files": 0}
    else:
        total = files = 0
        for root, _dirs, names in os.walk(path):
            for n in names:
                try:
                    total += os.lstat(os.path.join(root, n)).st_size
                    files += 1
                except OSError:
                    pass
        val = {"exists": True, "bytes": total, "files": files}
    _folder_size_cache[path] = {"at": now, "val": val}
    return val


@app.get("/admin/folder-sizes/{kind}")
def get_folder_sizes(kind: str, db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    """Map of username -> {exists, bytes, files} for trusted or private users' home folders."""
    if kind == "trusted":
        model, mount = TrustedFtpUser, settings.ftp_base_mount
    elif kind == "private":
        model, mount = PrivateFtpUser, settings.private_ftp_base_mount
    else:
        raise HTTPException(status_code=404, detail="Unknown user class")
    mount = os.path.realpath(mount)
    out = {}
    for user in db.query(model).all():
        full_path = os.path.normpath(os.path.join(mount, user.ftp_home_dir))
        if not full_path.startswith(mount + os.sep):
            continue
        out[user.username] = _folder_size(full_path)
    return out


@app.get("/admin/users/{user_id}/downloads")
def user_download_history(
    user_id: str, limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db), _: str = Depends(get_current_admin),
):
    user = get_user_or_404(user_id, db)
    try:
        return ftplogs.get_user_downloads_for_user(user.username, limit=limit)
    except Exception as e:
        _logs_err(e)


# ── Admin — FTP bans (anonymous idle / reconnect abuse) ───────────────────────
# Detection + nftables enforcement run on the host (ftpban/ftpban.py); these
# routes read/write its SQLite DB. Changes take effect within ~2s.

def _ftpban(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ftpban.FtpBanUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/admin/ftpban/status")
def ftpban_status(_: str = Depends(get_current_admin)):
    return _ftpban(ftpban.get_status)


@app.get("/admin/ftpban/watchlist")
def ftpban_watchlist(_: str = Depends(get_current_admin)):
    return _ftpban(ftpban.get_watchlist)


@app.get("/admin/ftpban/bans")
def ftpban_list(
    state: str = Query("active", pattern="^(active|history|all)$"),
    ip: Optional[str] = Query(None, max_length=64),
    source: Optional[str] = Query(None, pattern="^(auto|manual|dry_run)$"),
    limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
    _: str = Depends(get_current_admin),
):
    return _ftpban(ftpban.list_bans, state=state, ip=ip, source=source, limit=limit, offset=offset)


@app.post("/admin/ftpban/bans", status_code=201)
def ftpban_manual(body: FtpBanManualRequest, request: Request,
                  db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    by = get_admin_username(db)
    ban = _ftpban(ftpban.manual_ban, body.ip, body.duration_minutes, body.reason, by)
    dur = f"{body.duration_minutes} min" if body.duration_minutes else "permanent"
    audit(db, by, "ftpban_manual", f"{body.ip} ({dur}) {body.reason or ''}".strip(), get_real_ip(request))
    return ban


@app.delete("/admin/ftpban/bans/{ban_id}", response_model=MessageResponse)
def ftpban_unban(ban_id: int, request: Request,
                 db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    by = get_admin_username(db)
    ban = _ftpban(ftpban.unban, ban_id, by)
    if not ban:
        raise HTTPException(status_code=404, detail="No active ban with that id")
    audit(db, by, "ftpban_unban", ban["ip"], get_real_ip(request))
    return {"message": f"Unbanned {ban['ip']}"}


@app.post("/admin/ftpban/unban-ip", response_model=MessageResponse)
def ftpban_unban_ip(body: FtpBanUnbanIPRequest, request: Request,
                    db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    by = get_admin_username(db)
    n = _ftpban(ftpban.unban_ip, body.ip, by)
    if not n:
        raise HTTPException(status_code=404, detail="That IP has no active ban")
    audit(db, by, "ftpban_unban", body.ip.strip(), get_real_ip(request))
    return {"message": f"Unbanned {body.ip.strip()}"}


@app.put("/admin/ftpban/bans/{ban_id}/expiry")
def ftpban_expiry(ban_id: int, body: FtpBanExpiryRequest, request: Request,
                  db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    by = get_admin_username(db)
    ban = _ftpban(ftpban.set_expiry, ban_id, body.duration_minutes, body.enforce)
    if not ban:
        raise HTTPException(status_code=404, detail="No active ban with that id")
    dur = f"{body.duration_minutes} min from now" if body.duration_minutes else "permanent"
    audit(db, by, "ftpban_expiry", f"{ban['ip']} -> {dur}{' (enforced)' if body.enforce else ''}", get_real_ip(request))
    return ban


@app.get("/admin/ftpban/offenders")
def ftpban_offenders(days: int = Query(7, ge=1, le=3650),
                     sort: str = Query("total", pattern="^(total|bans|notransfer|idle|connect|aborted)$"),
                     limit: int = Query(50, ge=1, le=500),
                     _: str = Depends(get_current_admin)):
    return _ftpban(ftpban.top_offenders, days=days, sort=sort, limit=limit)


@app.get("/admin/ftpban/timeline")
def ftpban_timeline(days: int = Query(30, ge=1, le=3650), _: str = Depends(get_current_admin)):
    return _ftpban(ftpban.timeline, days=days)


@app.get("/admin/ftpban/ip/{ip}")
def ftpban_ip(ip: str, _: str = Depends(get_current_admin)):
    return _ftpban(ftpban.ip_detail, ip)


@app.post("/admin/ftpban/watchdog/retry", response_model=MessageResponse)
def ftpban_watchdog_retry(request: Request, db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    _ftpban(ftpban.request_watchdog_retry)
    audit(db, get_admin_username(db), "ftpban_watchdog_retry", None, get_real_ip(request))
    return {"message": "Recovery requested — the watchdog retries within 30 seconds"}


@app.get("/admin/ftpban/whitelist")
def ftpban_get_whitelist(request: Request, _: str = Depends(get_current_admin)):
    return {"entries": _ftpban(ftpban.get_whitelist), "your_ip": get_real_ip(request)}


@app.post("/admin/ftpban/whitelist", response_model=MessageResponse, status_code=201)
def ftpban_add_whitelist(body: WhitelistIPRequest, request: Request,
                         db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    by = get_admin_username(db)
    r = _ftpban(ftpban.add_whitelist, body.cidr, body.notes, by)
    audit(db, by, "ftpban_whitelist_add",
          f"{body.cidr}" + (f" (lifted {r['lifted']} auto ban(s))" if r["lifted"] else ""), get_real_ip(request))
    msg = f"{body.cidr} whitelisted — applied within a few seconds"
    if r["lifted"]:
        msg += f"; lifted {r['lifted']} active auto ban{'s' if r['lifted'] != 1 else ''}"
    return {"message": msg}


@app.delete("/admin/ftpban/whitelist", response_model=MessageResponse)
def ftpban_remove_whitelist(request: Request, entry: str = Query(..., max_length=64),
                            db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    by = get_admin_username(db)
    if not _ftpban(ftpban.remove_whitelist, entry, by):
        raise HTTPException(status_code=404, detail="Not on the whitelist")
    audit(db, by, "ftpban_whitelist_remove", entry.strip(), get_real_ip(request))
    return {"message": f"{entry.strip()} removed from the FTP whitelist"}


@app.get("/admin/ftpban/settings")
def ftpban_get_settings(_: str = Depends(get_current_admin)):
    return _ftpban(ftpban.get_settings)


@app.put("/admin/ftpban/settings", response_model=MessageResponse)
def ftpban_put_settings(body: FtpBanSettings, request: Request,
                        db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    by = get_admin_username(db)
    _ftpban(ftpban.save_settings, body.model_dump(), by)
    audit(db, by, "ftpban_settings", f"enforce={body.enforce}", get_real_ip(request))
    return {"message": "Ban settings saved — applied within a few seconds"}


# ── Admin — live FTP sessions (ftpwho) ────────────────────────────────────────
# The JSON snapshot is written by the host-side exporter (ftpwho/ftpwho-export.py),
# since ProFTPd and its scoreboard live on the host, not in this stack.

FTPWHO_STALE_MS = 10_000


def _ftpwho_conn(c: dict, trusted: set, registered: set, private: set) -> dict:
    user = c.get("user") or ""
    if user == "anonftp":
        user_class = "anon"
    elif user in trusted:
        user_class = "trusted"
    elif user in private:
        user_class = "private"
    elif user in registered:
        user_class = "registered"
    else:
        user_class = "other" if user else "auth"

    if c.get("downloading"):
        state = "download"
    elif c.get("uploading"):
        state = "upload"
    elif c.get("idling"):
        state = "idle"
    elif not user:
        state = "auth"
    else:
        state = "command"

    # ftpwho 1.3.8's "transfer_duration_ms" is actually microseconds.
    xfer_us = c.get("transfer_duration_ms")
    xfer_ms = int(xfer_us / 1000) if isinstance(xfer_us, (int, float)) else None
    xfer_bytes = c.get("transfer_bytes") if state in ("download", "upload") else None
    if state in ("download", "upload") and xfer_bytes is None:
        xfer_bytes = 0
    rate = int(xfer_bytes * 1000 / xfer_ms) if xfer_bytes and xfer_ms else None
    try:
        pct = int(c["transfer_completed"])
    except (KeyError, TypeError, ValueError):
        pct = None

    # Prefer the exporter's kernel-side numbers ("io", from /proc): under
    # UseSendFile the scoreboard hardly updates transfer bytes, so the values
    # above sit at 0 / None for hours on large downloads.
    io = c.get("io") or {}
    f = io.get("file") or {}
    io_rate = io.get("rate_in") if state == "upload" else io.get("rate_out")
    if state in ("download", "upload"):
        if f:
            xfer_bytes, pct = f.get("offset"), f.get("pct")
        if io_rate is not None:
            rate = io_rate

    return {
        "pid":                c.get("pid"),
        "user":               user,
        "user_class":         user_class,
        "remote_address":     c.get("remote_address"),
        "remote_name":        c.get("remote_name"),
        "protocol":           c.get("protocol"),
        "location":           c.get("location"),
        "state":              state,
        "command":            c.get("command"),
        "command_args":       c.get("command_args"),
        "connected_since_ms": c.get("connected_since_ms"),
        "idle_since_ms":      c.get("idle_since_ms"),
        "transfer_bytes":     xfer_bytes,
        "transfer_ms":        xfer_ms,
        "transfer_pct":       pct,
        "rate_bps":           rate,
        "file_size":          f.get("size"),
        "file_path":          f.get("path"),
        "progress_approx":    bool(f.get("approx")),
        "session_bytes_out":  io.get("bytes_out"),
        "session_bytes_in":   io.get("bytes_in"),
        "last_io_ms":         io.get("last_io_ms"),
        "cmd_since_ms":       io.get("cmd_since_ms"),
        "cmd_since_approx":   bool(io.get("cmd_since_approx")),
    }


@app.get("/admin/ftpwho")
def get_ftpwho(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    import json, time
    now_ms = int(time.time() * 1000)
    try:
        with open(settings.ftpwho_json_path) as f:
            snap = json.load(f)
    except FileNotFoundError:
        return {"ok": False, "stale": True, "now_ms": now_ms, "generated_ms": None,
                "error": "No ftpwho snapshot found — is the ciosuseradd-ftpwho exporter running on the host?",
                "server": None, "connections": []}
    except Exception as e:
        return {"ok": False, "stale": True, "now_ms": now_ms, "generated_ms": None,
                "error": f"Could not read ftpwho snapshot: {e}", "server": None, "connections": []}

    trusted    = {u for (u,) in db.query(TrustedFtpUser.username).all()}
    registered = {u for (u,) in db.query(User.username).all()}
    private    = {u for (u,) in db.query(PrivateFtpUser.username).all()}
    generated  = snap.get("generated_ms") or 0
    return {
        "ok":           bool(snap.get("ok")),
        "error":        snap.get("error"),
        "now_ms":       now_ms,
        "generated_ms": generated,
        "stale":        now_ms - generated > FTPWHO_STALE_MS,
        "server":       snap.get("server"),
        "connections":  [_ftpwho_conn(c, trusted, registered, private) for c in snap.get("connections") or []],
    }


# ── Admin — database status ───────────────────────────────────────────────────

@app.get("/admin/db/stats")
def get_db_stats(_: str = Depends(get_current_admin)):
    try:
        return ftplogs.get_db_stats()
    except Exception as e:
        _logs_err(e)


# ── Admin — settings ──────────────────────────────────────────────────────────

@app.get("/admin/settings", response_model=SystemSettingsResponse)
def get_settings(db: Session = Depends(get_db), _: str = Depends(get_current_admin)):
    try:
        status = ftplogs.get_system_status()
    except Exception:
        status = {
            "log_filename": "unavailable", "log_retention_days": 90,
            "tailer_status": "unavailable", "tailer_last_write": "",
            "tailer_pos": 0, "tailer_total_rows": 0,
        }
    return {
        "admin_username":    get_admin_username(db),
        **status,
    }


@app.put("/admin/settings/password", response_model=MessageResponse)
def admin_change_password(
    body: AdminChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    admin_user = get_admin_username(db)
    if not verify_admin(admin_user, body.current_password, db):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    change_admin_password(body.new_password, db)
    audit(db, "admin", "admin_password_change", "admin changed their own password",
          get_real_ip(request))
    return {"message": "Admin password updated successfully"}


@app.put("/admin/settings/username", response_model=MessageResponse)
def admin_change_username(
    body: AdminChangeUsernameRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    old = get_admin_username(db)
    change_admin_username(body.new_username, db)
    audit(db, "admin", "admin_username_change", f"{old} → {body.new_username}",
          get_real_ip(request))
    return {"message": f"Admin username changed to {body.new_username}"}


@app.put("/admin/settings/logs", response_model=MessageResponse)
def update_log_settings(
    body: LogSettingsRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_admin),
):
    try:
        ftplogs.update_log_settings(
            body.log_filename, body.log_retention_days,
            body.log_retention_enabled,
            body.http_log_filename, body.http_log_enabled,
        )
    except Exception as e:
        _logs_err(e)
    parts = []
    if body.log_filename:
        parts.append(f"log_filename={body.log_filename}")
    if body.log_retention_days:
        parts.append(f"retention={body.log_retention_days}d")
    audit(db, "admin", "log_settings_change", ", ".join(parts), get_real_ip(request))
    return {"message": "Log settings updated"}


# ── Admin — FTP activity: paginated tables ────────────────────────────────────

@app.get("/admin/logs/users", response_model=UserDownloadPage)
def log_user_downloads(
    page: int = Query(1, ge=1), limit: int = Query(100, ge=1, le=500),
    username: Optional[str] = Query(None), ip: Optional[str] = Query(None),
    filename: Optional[str] = Query(None),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    exclude_username: Optional[str] = Query(None),
    username_exact: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_user_downloads(page=page, limit=limit, username=username,
                                          ip=ip, filename=filename, source=source,
                                          date_from=date_from, date_to=date_to,
                                          exclude_username=exclude_username,
                                          username_exact=username_exact)
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/users/stats", response_model=UserDownloadStats)
def log_user_stats(
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    sort_files_by: str = Query("downloads", pattern="^(downloads|bytes)$"),
    sort_users_by: str = Query("downloads", pattern="^(downloads|bytes)$"),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
    exclude_username: Optional[str] = Query(None),
    username_exact: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_user_download_stats(
            date_from=date_from, date_to=date_to,
            sort_files_by=sort_files_by, sort_users_by=sort_users_by,
            source=source, exclude_username=exclude_username,
            username_exact=username_exact,
        )
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/users/export")
def export_user_downloads(
    username: Optional[str] = Query(None), ip: Optional[str] = Query(None),
    filename: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        csv_data = ftplogs.export_user_downloads_csv(
            username=username, ip=ip, filename=filename,
            date_from=date_from, date_to=date_to)
    except Exception as e:
        _logs_err(e)
    return StreamingResponse(
        iter([csv_data]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=user_downloads.csv"},
    )


# ── Admin — R/W activity log (trusted + private users) ────────────────────────

def _activity_filters(username, user_class, action, ip, path, result, date_from, date_to):
    return dict(username=username, user_class=user_class, action=action, ip=ip, path=path,
                result=result, date_from=date_from, date_to=date_to)


@app.get("/admin/activity")
def activity_log(
    page: int = Query(1, ge=1), limit: int = Query(100, ge=1, le=500),
    username: Optional[str] = Query(None, max_length=64),
    user_class: Optional[str] = Query(None, pattern="^(trusted|private)$"),
    action: Optional[str] = Query(None, max_length=100),
    ip: Optional[str] = Query(None, max_length=64),
    path: Optional[str] = Query(None, max_length=500),
    result: Optional[str] = Query(None, pattern="^(ok|fail)$"),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        data = ftplogs.get_activity(page=page, limit=limit, **_activity_filters(
            username, user_class, action, ip, path, result, date_from, date_to))
        data["backfill"] = ftplogs.get_activity_backfill_status()
        return data
    except Exception as e:
        _logs_err(e)


@app.get("/admin/activity/summary")
def activity_summary(
    days: int = Query(30, ge=1, le=3650),
    user_class: Optional[str] = Query(None, pattern="^(trusted|private)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_activity_summary(days=days, user_class=user_class)
    except Exception as e:
        _logs_err(e)


@app.get("/admin/activity/export")
def activity_export(
    username: Optional[str] = Query(None, max_length=64),
    user_class: Optional[str] = Query(None, pattern="^(trusted|private)$"),
    action: Optional[str] = Query(None, max_length=100),
    ip: Optional[str] = Query(None, max_length=64),
    path: Optional[str] = Query(None, max_length=500),
    result: Optional[str] = Query(None, pattern="^(ok|fail)$"),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        csv_data = ftplogs.export_activity_csv(**_activity_filters(
            username, user_class, action, ip, path, result, date_from, date_to))
    except Exception as e:
        _logs_err(e)
    return StreamingResponse(
        iter([csv_data]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ftp_activity.csv"},
    )


@app.get("/admin/logs/anon", response_model=AnonDownloadPage)
def log_anon_downloads(
    page: int = Query(1, ge=1), limit: int = Query(100, ge=1, le=500),
    ip: Optional[str] = Query(None), filename: Optional[str] = Query(None),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_anon_downloads(page=page, limit=limit, ip=ip,
                                          filename=filename, source=source,
                                          date_from=date_from, date_to=date_to)
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/anon/stats", response_model=AnonDownloadStats)
def log_anon_stats(
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    sort_files_by: str = Query("downloads", pattern="^(downloads|bytes)$"),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_anon_download_stats(
            date_from=date_from, date_to=date_to,
            sort_files_by=sort_files_by, source=source,
        )
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/anon/export")
def export_anon_downloads(
    ip: Optional[str] = Query(None), filename: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        csv_data = ftplogs.export_anon_downloads_csv(
            ip=ip, filename=filename, date_from=date_from, date_to=date_to)
    except Exception as e:
        _logs_err(e)
    return StreamingResponse(
        iter([csv_data]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=anon_downloads.csv"},
    )


# ── Admin — FTP uploads ────────────────────────────────────────────────────────

@app.get("/admin/logs/uploads", response_model=UserUploadPage)
def log_user_uploads(
    page: int = Query(1, ge=1), limit: int = Query(100, ge=1, le=500),
    username: Optional[str] = Query(None), ip: Optional[str] = Query(None),
    filename: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_user_uploads(page=page, limit=limit, username=username,
                                        ip=ip, filename=filename,
                                        date_from=date_from, date_to=date_to)
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/uploads/stats", response_model=UserUploadStats)
def log_user_upload_stats(
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    sort_files_by: str = Query("downloads", pattern="^(downloads|bytes)$"),
    sort_users_by: str = Query("downloads", pattern="^(downloads|bytes)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_user_upload_stats(
            date_from=date_from, date_to=date_to,
            sort_files_by=sort_files_by, sort_users_by=sort_users_by,
        )
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/uploads/timeline")
def log_upload_timeline(
    days: int = Query(30, ge=1, le=3650),
    bucket: str = Query("day", pattern="^(hour|day|week)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_upload_timeline(days=days, bucket=bucket)
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/uploads/export")
def export_user_uploads(
    username: Optional[str] = Query(None), ip: Optional[str] = Query(None),
    filename: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        csv_data = ftplogs.export_user_uploads_csv(
            username=username, ip=ip, filename=filename,
            date_from=date_from, date_to=date_to)
    except Exception as e:
        _logs_err(e)
    return StreamingResponse(
        iter([csv_data]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=user_uploads.csv"},
    )


@app.get("/admin/logs/uploads/anon", response_model=AnonUploadPage)
def log_anon_uploads(
    page: int = Query(1, ge=1), limit: int = Query(100, ge=1, le=500),
    ip: Optional[str] = Query(None), filename: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_anon_uploads(page=page, limit=limit, ip=ip,
                                        filename=filename,
                                        date_from=date_from, date_to=date_to)
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/uploads/anon/stats", response_model=AnonUploadStats)
def log_anon_upload_stats(
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    sort_files_by: str = Query("downloads", pattern="^(downloads|bytes)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_anon_upload_stats(
            date_from=date_from, date_to=date_to, sort_files_by=sort_files_by,
        )
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/uploads/anon/export")
def export_anon_uploads(
    ip: Optional[str] = Query(None), filename: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None), date_to: Optional[str] = Query(None),
    _: str = Depends(get_current_admin),
):
    try:
        csv_data = ftplogs.export_anon_uploads_csv(
            ip=ip, filename=filename, date_from=date_from, date_to=date_to)
    except Exception as e:
        _logs_err(e)
    return StreamingResponse(
        iter([csv_data]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=anon_uploads.csv"},
    )


# ── Admin — FTP activity: time-series & dashboard ─────────────────────────────

@app.get("/admin/logs/summary", response_model=SummaryResponse)
def log_summary(
    days: int = Query(30, ge=1, le=3650),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_summary(days=days, source=source)
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/users/timeline")
def log_user_timeline(
    days: int = Query(30, ge=1, le=3650),
    bucket: str = Query("day", pattern="^(hour|day|week)$"),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_user_download_timeline(days=days, bucket=bucket, source=source)
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/anon/timeline")
def log_anon_timeline(
    days: int = Query(30, ge=1, le=3650),
    bucket: str = Query("day", pattern="^(hour|day|week)$"),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_anon_download_timeline(days=days, bucket=bucket, source=source)
    except Exception as e:
        _logs_err(e)


@app.get("/admin/logs/users/breakdown")
def log_user_breakdown(
    days: int = Query(30, ge=1, le=3650),
    sort_by: str = Query("downloads", pattern="^(downloads|bytes)$"),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_user_download_breakdown(days=days, sort_by=sort_by, source=source)
    except Exception as e:
        _logs_err(e)


def _heatmap(source: str, tz: Optional[str], days: Optional[int],
             start: Optional[datetime], end: Optional[datetime]):
    if start and end and start >= end:
        raise HTTPException(status_code=422, detail="start must be before end")
    try:
        return ftplogs.get_activity_heatmap(source=source, tz=tz, days=days, start=start, end=end)
    except Exception as e:
        _logs_err(e)


# Range: start/end (ISO datetimes; naive = UTC) for a custom range, else days,
# else all history. Cheap for any range — it slices one cached hourly series.
@app.get("/admin/logs/heatmap")
def log_heatmap(
    source: str = Query(..., pattern="^(ftp|http)$"),
    tz: Optional[str] = Query(None, max_length=64),
    days: Optional[int] = Query(None, ge=1, le=3650),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    _: str = Depends(get_current_admin),
):
    return _heatmap(source, tz, days, start, end)


@app.get("/admin/logs/earliest")
def log_earliest(
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
    _: str = Depends(get_current_admin),
):
    try:
        return ftplogs.get_earliest_activity(source=source)
    except Exception as e:
        _logs_err(e)


# ── Public overview (unauthenticated, anonymized) ─────────────────────────────
# Backs the shareable read-only copy of the General Overview page. Same
# cached data as the admin endpoints, but IPs and usernames are masked
# before they ever leave this process — never cached or logged unmasked
# under a public route.

def _mask_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return ip
    if "." in ip:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.x.x"
        return ip
    if ":" in ip:
        parts = ip.split(":")
        keep = max(1, len(parts) - 2)
        return ":".join(parts[:keep] + ["x"] * (len(parts) - keep))
    return ip


def _mask_username(u: Optional[str]) -> Optional[str]:
    if not u:
        return u
    if len(u) == 1:
        return u + "****"
    return u[0] + "****" + u[-1]


def _private_usernames() -> set:
    db = SessionLocal()
    try:
        return {u for (u,) in db.query(PrivateFtpUser.username).all()}
    finally:
        db.close()


def _is_private_path(path: Optional[str]) -> bool:
    base = settings.private_ftp_base_path.rstrip("/")
    return bool(path) and (path == base or path.startswith(base + "/"))


@app.get("/public/site")
def public_site():
    """Branding + public settings both frontends need at load time."""
    return {
        "site_name":            settings.site_name,
        "ftp_public_host":      settings.ftp_public_host,
        "public_http_username": settings.public_http_username,
        "ftp_base_path":        settings.ftp_base_path.rstrip("/"),
        "wrong_portal_name":    settings.wrong_portal_name,
        "wrong_portal_url":     settings.wrong_portal_url,
    }


# `minutes` overrides `days` on the routes below. Only fixed windows are
# accepted: this is unauthenticated, and each distinct window is a cache key
# (and, for top-stats on a long window, about a minute of DB work).
_PUBLIC_TOP_STATS_DAYS = (1, 7, 30, 365)


def _check_public_minutes(minutes: Optional[int]) -> None:
    if minutes is not None and minutes not in ftplogs.MINUTE_WINDOWS:
        raise HTTPException(status_code=422, detail="Unsupported time window")


@app.get("/public/overview/summary")
def public_overview_summary(
    days: int = Query(30, ge=1, le=3650),
    minutes: Optional[int] = Query(None),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
):
    _check_public_minutes(minutes)
    try:
        return ftplogs.get_summary(days=days, source=source, minutes=minutes)
    except Exception as e:
        _logs_err(e)


@app.get("/public/overview/users/timeline")
def public_overview_user_timeline(
    days: int = Query(30, ge=1, le=3650),
    minutes: Optional[int] = Query(None),
    bucket: str = Query("day", pattern="^(hour|day|week)$"),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
):
    _check_public_minutes(minutes)
    try:
        return ftplogs.get_user_download_timeline(days=days, bucket=bucket, source=source, minutes=minutes)
    except Exception as e:
        _logs_err(e)


@app.get("/public/overview/anon/timeline")
def public_overview_anon_timeline(
    days: int = Query(30, ge=1, le=3650),
    minutes: Optional[int] = Query(None),
    bucket: str = Query("day", pattern="^(hour|day|week)$"),
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
):
    _check_public_minutes(minutes)
    try:
        return ftplogs.get_anon_download_timeline(days=days, bucket=bucket, source=source, minutes=minutes)
    except Exception as e:
        _logs_err(e)


@app.get("/public/overview/users/breakdown")
def public_overview_user_breakdown(
    days: int = Query(30, ge=1, le=3650),
    minutes: Optional[int] = Query(None),
    sort_by: str = Query("downloads", pattern="^(downloads|bytes)$"),
):
    _check_public_minutes(minutes)
    try:
        rows = ftplogs.get_user_download_breakdown(days=days, sort_by=sort_by, source=None, minutes=minutes)
        private = _private_usernames()
        return [{**r, "username": _mask_username(r.get("username"))}
                for r in rows if r.get("username") not in private]
    except Exception as e:
        _logs_err(e)


@app.get("/public/overview/top-stats")
def public_overview_top_stats(
    sort_files_by: str = Query("downloads", pattern="^(downloads|bytes)$"),
    days: Optional[int] = Query(None),
    minutes: Optional[int] = Query(None),
):
    _check_public_minutes(minutes)
    if days is not None and days not in _PUBLIC_TOP_STATS_DAYS:
        raise HTTPException(status_code=422, detail="Unsupported time window")
    try:
        data = dict(ftplogs.get_user_download_stats(sort_files_by=sort_files_by, days=days, minutes=minutes))
        private = _private_usernames()
        data["top_files"] = [r for r in data.get("top_files", []) if not _is_private_path(r.get("filepath"))]
        data["top_users"] = [r for r in data.get("top_users", []) if r.get("username") not in private]
        data["top_ips"] = [{**r, "ip_address": _mask_ip(r.get("ip_address"))} for r in data.get("top_ips", [])]
        data["top_users"] = [{**r, "username": _mask_username(r.get("username"))} for r in data.get("top_users", [])]
        return data
    except Exception as e:
        _logs_err(e)


# Aggregate counts only (no IPs/usernames), so nothing to mask.
@app.get("/public/overview/heatmap")
def public_overview_heatmap(
    source: str = Query(..., pattern="^(ftp|http)$"),
    tz: Optional[str] = Query(None, max_length=64),
    days: Optional[int] = Query(None, ge=1, le=3650),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
):
    return _heatmap(source, tz, days, start, end)


@app.get("/public/overview/earliest")
def public_overview_earliest(
    source: Optional[str] = Query(None, pattern="^(ftp|http)$"),
):
    try:
        return ftplogs.get_earliest_activity(source=source)
    except Exception as e:
        _logs_err(e)


@app.get("/public/overview/snapshot")
def public_overview_snapshot(db: Session = Depends(get_db)):
    total   = db.query(func.count(User.id)).scalar()
    enabled = db.query(func.count(User.id)).filter(User.enabled == True).scalar()
    trusted_total = db.query(func.count(TrustedFtpUser.id)).scalar()
    db_bytes = 0
    try:
        db_bytes = ftplogs.get_db_stats().get("db_bytes", 0)
    except Exception:
        pass
    return {"total": total, "enabled": enabled, "trusted_total": trusted_total, "db_bytes": db_bytes}
