"""
backend/auth.py

Authentication helpers: bcrypt, JWT, and admin credential management.
Admin credentials are stored in the admin_config table (seeded from env
on first start). After first start the UI manages them exclusively.
"""

import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from config import settings

# ── Bcrypt ────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


# ── Admin credentials (DB-backed) ─────────────────────────────────────────────

def _get_config(db: Session, key: str) -> Optional[str]:
    from models import AdminConfig
    row = db.query(AdminConfig).filter(AdminConfig.key == key).first()
    return row.value if row else None


def _set_config(db: Session, key: str, value: str):
    from models import AdminConfig
    row = db.query(AdminConfig).filter(AdminConfig.key == key).first()
    if row:
        row.value = value
        row.updated_at = datetime.now(timezone.utc)
    else:
        db.add(AdminConfig(key=key, value=value))
    db.commit()


def seed_admin_config(db: Session):
    """
    Called once at startup. If admin credentials don't exist in the DB yet,
    seed them from environment variables. After first seed, env vars are ignored.
    """
    from models import AdminConfig
    existing = db.query(AdminConfig).filter(
        AdminConfig.key == "admin_username"
    ).first()
    if not existing:
        db.add(AdminConfig(key="admin_username", value=settings.admin_username))
        db.add(AdminConfig(key="admin_password_hash",
                           value=hash_password(settings.admin_password)))
        db.commit()


def verify_admin(username: str, password: str, db: Session) -> bool:
    """Constant-time admin credential check against the DB."""
    stored_user = _get_config(db, "admin_username") or ""
    stored_hash = _get_config(db, "admin_password_hash") or ""

    # Always run both checks to avoid timing side-channels
    username_ok = hmac.compare_digest(username.lower(), stored_user.lower())
    password_ok = verify_password(password, stored_hash) if stored_hash else False

    # Burn time even on username mismatch
    if not username_ok:
        secrets.token_bytes(32)

    return username_ok and password_ok


def change_admin_password(new_password: str, db: Session):
    _set_config(db, "admin_password_hash", hash_password(new_password))


def change_admin_username(new_username: str, db: Session):
    _set_config(db, "admin_username", new_username)


def get_admin_username(db: Session) -> str:
    return _get_config(db, "admin_username") or settings.admin_username


# ── JWT ───────────────────────────────────────────────────────────────────────

ALGORITHM   = "HS256"
TOKEN_HOURS = 2


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None
