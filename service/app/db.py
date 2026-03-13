from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, AsyncIterator, Optional

from sqlalchemy import JSON, DateTime, String, Text, UniqueConstraint, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.settings import settings


class Base(DeclarativeBase):
    pass


class OAuthState(Base):
    __tablename__ = "oauth_states"

    state: Mapped[str] = mapped_column(String(128), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))


class MailConnection(Base):
    __tablename__ = "mail_connections"
    __table_args__ = (
        UniqueConstraint("business_profile_id", "provider", "user_id", name="uq_mail_connection_bp_provider_user"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    business_profile_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)  # gmail|outlook|ses_forwarding
    token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    connected_email: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), onupdate=lambda: dt.datetime.now(dt.UTC))


_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(settings.MAILCLI_DATABASE_URL, future=True, echo=False)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _ensure_mail_connections_user_scope(conn)


async def _ensure_mail_connections_user_scope(conn: AsyncConnection) -> None:
    dialect_name = conn.dialect.name.lower()
    if dialect_name == "postgresql":
        await conn.execute(
            text(
                "ALTER TABLE mail_connections "
                "DROP CONSTRAINT IF EXISTS uq_mail_connection_bp_provider"
            )
        )
        await conn.execute(
            text(
                "ALTER TABLE mail_connections "
                "DROP CONSTRAINT IF EXISTS uq_mail_connection_bp_provider_user"
            )
        )
        await conn.execute(
            text(
                """
                DO $$
                BEGIN
                    ALTER TABLE mail_connections
                    ADD CONSTRAINT uq_mail_connection_bp_provider_user
                    UNIQUE (business_profile_id, provider, user_id);
                EXCEPTION
                    WHEN duplicate_object THEN NULL;
                END $$;
                """
            )
        )


async def session_scope() -> AsyncIterator[AsyncSession]:
    Session = get_sessionmaker()
    async with Session() as session:
        yield session
