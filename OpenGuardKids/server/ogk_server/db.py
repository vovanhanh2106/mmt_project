"""Mô hình dữ liệu SQLAlchemy 2.0 – 1 phụ huynh : n trẻ : m thiết bị. SQLite chế độ WAL."""
from __future__ import annotations
import time
from sqlalchemy import BigInteger, Boolean, ForeignKey, Index, Integer, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def now() -> int: return int(time.time())


class Base(DeclarativeBase):
    pass


class Parent(Base):
    __tablename__ = "parents"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(100))
    pw_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(10), default="parent")          # parent | admin
    totp_secret_enc: Mapped[str | None] = mapped_column(String(200), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[int] = mapped_column(BigInteger, default=now)
    children: Mapped[list["Child"]] = relationship(back_populates="parent", cascade="all, delete-orphan")


class Child(Base):
    __tablename__ = "children"
    id: Mapped[int] = mapped_column(primary_key=True)
    parent_id: Mapped[int] = mapped_column(ForeignKey("parents.id"), index=True)
    name_enc: Mapped[str] = mapped_column(String(300))                       # AES-GCM
    age_band: Mapped[str] = mapped_column(String(10), default="6-11")
    created_at: Mapped[int] = mapped_column(BigInteger, default=now)
    parent: Mapped[Parent] = relationship(back_populates="children")
    devices: Mapped[list["Device"]] = relationship(back_populates="child", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    child_id: Mapped[int] = mapped_column(ForeignKey("children.id"), index=True)
    hostname: Mapped[str] = mapped_column(String(100))
    fingerprint_hash: Mapped[str] = mapped_column(String(64))
    policy_key_enc: Mapped[str] = mapped_column(String(200))                 # khoá HMAC chính sách, AES-GCM
    enrolled_at: Mapped[int] = mapped_column(BigInteger, default=now)
    last_seen: Mapped[int] = mapped_column(BigInteger, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str] = mapped_column(String(20), default="unknown")
    policy_version_ack: Mapped[int] = mapped_column(Integer, default=0)
    child: Mapped[Child] = relationship(back_populates="devices")


class PairingCode(Base):
    __tablename__ = "pairing_codes"
    id: Mapped[int] = mapped_column(primary_key=True)
    child_id: Mapped[int] = mapped_column(ForeignKey("children.id"))
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[int] = mapped_column(BigInteger)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[int] = mapped_column(BigInteger)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class SessionRec(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    parent_id: Mapped[int] = mapped_column(ForeignKey("parents.id"), index=True)
    csrf: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[int] = mapped_column(BigInteger)


class PolicyRec(Base):
    __tablename__ = "policies"
    id: Mapped[int] = mapped_column(primary_key=True)
    child_id: Mapped[int] = mapped_column(ForeignKey("children.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[int] = mapped_column(BigInteger, default=now)
    __table_args__ = (Index("ix_policy_child_version", "child_id", "version", unique=True),)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[int] = mapped_column(BigInteger, default=now, index=True)
    child_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    actor: Mapped[str] = mapped_column(String(120))
    ip: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(60))
    summary: Mapped[str] = mapped_column(String(300), default="")
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[int] = mapped_column(BigInteger, index=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True)
    child_id: Mapped[int] = mapped_column(Integer, index=True)
    type: Mapped[str] = mapped_column(String(20))
    subject: Mapped[str] = mapped_column(String(253))
    duration_sec: Mapped[int] = mapped_column(Integer, default=0)
    policy_id: Mapped[str | None] = mapped_column(String(20), nullable=True)


class IngestBatch(Base):
    __tablename__ = "ingest_batches"
    device_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    received_at: Mapped[int] = mapped_column(BigInteger, default=now)


class DailyUsage(Base):
    __tablename__ = "daily_usage"
    device_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    used_sec: Mapped[int] = mapped_column(Integer, default=0)
    child_id: Mapped[int] = mapped_column(Integer, index=True)


class ChildRequest(Base):
    __tablename__ = "child_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    child_id: Mapped[int] = mapped_column(Integer, index=True)
    device_id: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(20))        # more_time | unblock
    subject: Mapped[str] = mapped_column(String(120), default="")
    note: Mapped[str] = mapped_column(String(300), default="")
    status: Mapped[str] = mapped_column(String(10), default="pending")   # pending | approved | denied
    response_text: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[int] = mapped_column(BigInteger, default=now)
    resolved_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class Command(Base):
    __tablename__ = "commands"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(20))        # lock | unlock | add_time | pause | purge_data
    minutes: Mapped[int] = mapped_column(Integer, default=15)
    created_at: Mapped[int] = mapped_column(BigInteger, default=now)
    acked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


def make_engine(url: str):
    kw = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    eng = create_engine(url, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _pragma(conn, _):
            cur = conn.cursor(); cur.execute("PRAGMA journal_mode=WAL"); cur.execute("PRAGMA foreign_keys=ON"); cur.close()
    return eng


def make_session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)
