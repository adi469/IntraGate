"""Database engine and session management — async Scoped SQLAlchemy with asyncpg.

Supports concurrent multi-threaded event loops (e.g. running the User Portal
and Admin Panel on separate ports/threads in the same Python process).
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from .config import DATABASE_URL, GATEWAY_ENCRYPTION_KEY

log = logging.getLogger("gateway.database")

# Registry of engines and sessionmakers per event loop to avoid cross-loop future sharing
_engines: dict[asyncio.AbstractEventLoop, AsyncEngine] = {}
_sessionmakers: dict[asyncio.AbstractEventLoop, async_sessionmaker[AsyncSession]] = {}


def get_engine() -> AsyncEngine:
    """Retrieve or create an AsyncEngine bound to the current running event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Fallback if called outside an active event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    if loop not in _engines:
        kwargs = {}
        if DATABASE_URL and DATABASE_URL.startswith("postgresql"):
            kwargs["pool_size"] = 5
            kwargs["max_overflow"] = 10
        _engines[loop] = create_async_engine(
            DATABASE_URL,
            echo=False,
            **kwargs
        )
    return _engines[loop]


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Retrieve or create an async_sessionmaker bound to the current running event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    if loop not in _sessionmakers:
        _sessionmakers[loop] = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _sessionmakers[loop]


class LoopScopedSessionMaker:
    """Proxy callable that forwards to the loop-scoped async_sessionmaker."""
    def __call__(self, *args, **kwargs) -> AsyncSession:
        return get_sessionmaker()(*args, **kwargs)


class LoopScopedEngineProxy:
    """Proxy that forwards engine execution calls to the loop-scoped AsyncEngine."""
    @property
    def _engine(self) -> AsyncEngine:
        return get_engine()

    def begin(self):
        return self._engine.begin()

    async def dispose(self):
        """Dispose all active engines across all registered loops."""
        for loop, eng in list(_engines.items()):
            try:
                await eng.dispose()
            except Exception as e:
                log.warning("Failed to dispose engine on loop %s: %s", loop, e)
        _engines.clear()
        _sessionmakers.clear()
        log.info("All scoped database engines closed")


# Expose thread-safe and loop-scoped proxies with the same names
engine = LoopScopedEngineProxy()
AsyncSessionLocal = LoopScopedSessionMaker()


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields a DB session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create all tables if they don't exist and run seed logic."""
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Migrate existing DB: add upstream_scheme if not exists
        try:
            await conn.execute(
                text("ALTER TABLE applications ADD COLUMN IF NOT EXISTS upstream_scheme VARCHAR(10) NOT NULL DEFAULT 'http'")
            )
        except Exception as e:
            log.warning("Migration query failed: %s", e)
        # Migrate existing DB: add tls_verify if not exists
        try:
            await conn.execute(
                text("ALTER TABLE applications ADD COLUMN IF NOT EXISTS tls_verify BOOLEAN NOT NULL DEFAULT TRUE")
            )
        except Exception as e:
            log.warning("Migration for tls_verify failed: %s", e)
    log.info("Database tables initialized")

    # Run seed logic
    from .seed import seed_from_env
    async with AsyncSessionLocal() as session:
        await seed_from_env(session)

    # Encrypt existing plaintext Entra secrets in the database on startup
    from cryptography.fernet import Fernet
    from sqlalchemy import select

    from .db_models import EntraConfig

    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(EntraConfig))
            config_rows = result.scalars().all()
            for row in config_rows:
                if row.client_secret and not row.client_secret.startswith("gAAAAA"):
                    fernet = Fernet(GATEWAY_ENCRYPTION_KEY)
                    encrypted = fernet.encrypt(row.client_secret.encode()).decode()
                    row.client_secret = encrypted
            await session.commit()
        except Exception as e:
            log.warning("Failed to auto-encrypt Entra client secrets on startup: %s", e)


async def close_db():
    """Close the engine on shutdown."""
    await engine.dispose()
