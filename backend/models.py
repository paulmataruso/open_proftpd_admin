import uuid
from sqlalchemy import Column, String, Boolean, Text, DateTime, BigInteger, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from database import Base


class User(Base):
    __tablename__ = "users"

    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username           = Column(String(64), unique=True, nullable=False)
    email              = Column(String(255), unique=True, nullable=False)
    password_hash      = Column(Text, nullable=False)
    enabled            = Column(Boolean, nullable=False, default=True)
    created_at         = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login         = Column(DateTime(timezone=True), nullable=True)
    notes              = Column(Text, nullable=True)
    registered_from_ip = Column(String(45), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    username   = Column(String(64), nullable=True)
    action     = Column(String(64), nullable=False)
    detail     = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TrustedFtpUser(Base):
    __tablename__ = "trusted_ftp_users"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username      = Column(String(64), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    ftp_home_dir  = Column(Text, nullable=False)
    enabled       = Column(Boolean, nullable=False, default=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    notes         = Column(Text, nullable=True)


class AdminConfig(Base):
    __tablename__ = "admin_config"

    key        = Column(Text, primary_key=True)
    value      = Column(Text, nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(),
                        onupdate=func.now(), nullable=False)


class AdminIntrusionAttempt(Base):
    __tablename__ = "admin_intrusion_attempts"

    id                 = Column(BigInteger, primary_key=True, autoincrement=True)
    ip_address         = Column(String(45), nullable=False)
    username_attempted = Column(String(64), nullable=True)
    matched_user_id    = Column(UUID(as_uuid=True),
                                ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    warning_sent_at    = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    escalated_at       = Column(DateTime(timezone=True), nullable=True)
    account_disabled   = Column(Boolean, nullable=False, default=False)
    reviewed           = Column(Boolean, nullable=False, default=False)
    created_at         = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BannedIP(Base):
    __tablename__ = "banned_ips"

    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, nullable=False)
    reason     = Column(Text, nullable=True)
    banned_by  = Column(String(16), nullable=False, default="auto")
    notes      = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BannedUsername(Base):
    __tablename__ = "banned_usernames"

    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    username   = Column(String(64), unique=True, nullable=False)
    reason     = Column(Text, nullable=True)
    banned_by  = Column(String(16), nullable=False, default="auto")
    notes      = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
