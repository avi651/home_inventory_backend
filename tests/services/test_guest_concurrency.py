"""Concurrent guest sign-ins with real commits on separate connections (no rollback fixture)."""

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.rate_limit import InMemoryRateLimiter
from app.core.tokens import AccessTokenService
from app.models.auth_session import AuthSession
from app.models.user import User
from app.models.user_identity import UserIdentity
from app.services.auth_service import AuthService
from app.services.session_service import SessionService, TokenPair
from tests.conftest import GENEROUS_RATE_LIMITS
from tests.support.passwords import fast_hasher

CONCURRENT_GUESTS = 10


@pytest.fixture
async def factory(
    migrated_database: None, engine: AsyncEngine
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    # Guests created here are committed for real: remove them (sessions/tokens cascade).
    async with factory() as db:
        await db.execute(delete(User).where(User.id.in_(_created)))
        await db.commit()
    _created.clear()


_created: list[uuid.UUID] = []


async def sign_in(
    factory: async_sessionmaker[AsyncSession], settings: Settings
) -> tuple[uuid.UUID, TokenPair]:
    async with factory() as db:
        sessions = SessionService(db, AccessTokenService(settings), settings)
        service = AuthService(
            db,
            hasher=fast_hasher(),
            sessions=sessions,
            rate_limiter=InMemoryRateLimiter(),
            rate_limits=GENEROUS_RATE_LIMITS,
        )
        user, pair = await service.sign_in_as_guest()
        _created.append(user.id)
        return user.id, pair


async def test_concurrent_guests_get_independent_users_and_sessions(
    factory: async_sessionmaker[AsyncSession], test_settings: Settings
) -> None:
    results = await asyncio.gather(
        *(sign_in(factory, test_settings) for _ in range(CONCURRENT_GUESTS))
    )

    user_ids = [user_id for user_id, _ in results]
    session_ids = [pair.session_id for _, pair in results]
    assert len(set(user_ids)) == len(set(session_ids)) == CONCURRENT_GUESTS
    async with factory() as db:
        rows = (
            await db.execute(
                select(AuthSession.id, AuthSession.user_id).where(AuthSession.user_id.in_(user_ids))
            )
        ).all()
        assert {(row.id, row.user_id) for row in rows} == {
            (pair.session_id, user_id) for user_id, pair in results
        }
        guests = await db.execute(
            select(func.count()).where(User.id.in_(user_ids), User.is_guest.is_(True))
        )
        assert guests.scalar_one() == CONCURRENT_GUESTS
        identities = await db.execute(
            select(func.count()).where(UserIdentity.user_id.in_(user_ids))
        )
        assert identities.scalar_one() == 0
