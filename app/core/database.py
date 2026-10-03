from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings

CONNECT_TIMEOUT_SECONDS = 5
STATEMENT_TIMEOUT_MS = 15_000


def create_db_engine(settings: Settings) -> AsyncEngine:
    """Engine for the runtime (DML-only) role. Does not connect until first use."""
    return create_async_engine(
        settings.database_url.get_secret_value(),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        # Never render bound parameters (possibly PII or secrets) in exceptions or logs.
        hide_parameters=True,
        connect_args={
            "connect_timeout": CONNECT_TIMEOUT_SECONDS,
            # Server-side cap so a runaway query cannot hold a connection indefinitely.
            "options": f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
        },
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Request-scoped session; uncommitted work is rolled back when the session closes."""
    session_factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with session_factory() as session:
        yield session
