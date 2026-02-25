"""
db/database.py

Async SQLAlchemy setup for PostgreSQL.

Why async SQLAlchemy over a sync ORM:
- ATLAS uses FastAPI's async request handling throughout. A synchronous DB
  driver (psycopg2) would block the event loop during every DB query, nullifying
  the concurrency gains of async FastAPI and causing request queue buildup under
  SOC load (many analysts querying simultaneously during an incident).
- asyncpg + SQLAlchemy's async session give us true non-blocking DB I/O that
  cooperates with the event loop.

Session lifecycle:
- Each HTTP request gets its own AsyncSession via the `get_db` dependency.
- The session is committed/rolled back and closed in the finally block,
  ensuring connections are always returned to the pool — even on exceptions.
  This prevents connection pool exhaustion under error conditions.
"""

import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

# ─── Engine ───────────────────────────────────────────────────────────────────
# pool_pre_ping=True: before handing out a connection from the pool, SQLAlchemy
# sends a lightweight "SELECT 1" to verify the connection is still alive.
# This prevents "connection already closed" errors after Postgres restarts or
# idle connection timeouts — critical for a long-running SOC service.

engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,          # Max persistent connections — tune for your Postgres max_connections
    max_overflow=20,       # Extra connections allowed during traffic spikes
    pool_recycle=3600,     # Recycle connections every hour to avoid stale TCP timeouts
    echo=settings.debug,   # Log SQL statements in dev; NEVER in production (leaks query data)
)

# ─── Session Factory ──────────────────────────────────────────────────────────
# expire_on_commit=False: after commit(), SQLAlchemy normally expires all
# attributes, forcing a new SELECT on next access. Setting False lets us
# read the committed object's data in the same request without an extra query.

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ─── Declarative Base ─────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    """
    All ORM models inherit from this Base.
    Centralizing Base here means all models are discoverable by Alembic
    autogenerate for migration management.
    """
    pass


# ─── FastAPI Dependency ───────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Request-scoped database session dependency.

    Usage in a route:
        async def my_endpoint(db: AsyncSession = Depends(get_db)):

    The try/finally pattern guarantees the session is always closed,
    even when the route raises an unhandled exception — preventing
    connection pool exhaustion in the auth service.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ─── Schema Initialization ────────────────────────────────────────────────────

async def init_db() -> None:
    """
    Creates all tables defined in ORM models on first startup.

    This is intentionally simple — production deployments should use
    Alembic migrations (`alembic upgrade head`) instead of create_all(),
    which can't handle schema changes to existing tables.
    For a greenfield dev environment, create_all() is safe and fast.
    """
    # Import models here to register them with Base.metadata before create_all
    from app.db import models  # noqa: F401 — side-effect import registers models

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified / created.")
