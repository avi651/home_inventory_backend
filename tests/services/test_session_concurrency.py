"""Race-safety of rotation, using real commits on separate connections (no rollback fixture)."""

import asyncio
import uuid
from collections.abc import AsyncIterator, Callable

import pytest
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.refresh_tokens import hash_refresh_token
from app.core.tokens import AccessTokenService
from app.exceptions.errors import InvalidRefreshTokenError
from app.models.auth_session import AuthSession, SessionRevokeReason
from app.models.user import User
from app.services.session_service import SessionService, TokenPair
from tests.support.factories import create_user

ServiceFactory = Callable[[AsyncSession], SessionService]


@pytest.fixture
async def committed(
    migrated_database: None, engine: AsyncEngine
) -> AsyncIterator[tuple[async_sessionmaker[AsyncSession], list[uuid.UUID]]]:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    created_users: list[uuid.UUID] = []
    yield factory, created_users
    async with factory() as db:
        await db.execute(delete(User).where(User.id.in_(created_users)))
        await db.commit()


@pytest.fixture
def make_service(test_settings: Settings) -> ServiceFactory:
    access_tokens = AccessTokenService(test_settings)
    return lambda db: SessionService(db, access_tokens, test_settings)


async def start_committed_session(
    committed: tuple[async_sessionmaker[AsyncSession], list[uuid.UUID]],
    make_service: ServiceFactory,
) -> TokenPair:
    factory, created_users = committed
    async with factory() as db:
        user = await create_user(db)
        await db.commit()
        created_users.append(user.id)
        return await make_service(db).start(user.id)


async def attempt_refresh(
    factory: async_sessionmaker[AsyncSession], make_service: ServiceFactory, token: str
) -> TokenPair | BaseException:
    async with factory() as db:
        try:
            return await make_service(db).refresh(token)
        except Exception as exc:  # collected and asserted on by the caller
            return exc


async def test_concurrent_refreshes_cannot_both_succeed(
    committed: tuple[async_sessionmaker[AsyncSession], list[uuid.UUID]],
    make_service: ServiceFactory,
) -> None:
    factory, _ = committed
    pair = await start_committed_session(committed, make_service)

    results = await asyncio.gather(
        *(attempt_refresh(factory, make_service, pair.refresh_token) for _ in range(8))
    )

    successes = [r for r in results if isinstance(r, TokenPair)]
    rejections = [r for r in results if isinstance(r, InvalidRefreshTokenError)]
    unexpected = [r for r in results if not isinstance(r, TokenPair | InvalidRefreshTokenError)]
    assert unexpected == []  # no deadlocks, unique violations or other 500s
    assert len(successes) == 1
    assert len(rejections) == 7

    # Strict reuse policy (D3): the concurrent duplicates count as reuse and kill the session.
    async with factory() as db:
        auth_session = await db.get(AuthSession, pair.session_id)
        assert auth_session is not None
        assert auth_session.revoked_reason is SessionRevokeReason.REUSE_DETECTED
    assert isinstance(
        await attempt_refresh(factory, make_service, successes[0].refresh_token),
        InvalidRefreshTokenError,
    )


async def test_rotation_waits_for_a_competing_lock(
    committed: tuple[async_sessionmaker[AsyncSession], list[uuid.UUID]],
    make_service: ServiceFactory,
    engine: AsyncEngine,
) -> None:
    """Proves rotation takes a row lock: it blocks while another transaction holds it."""
    factory, _ = committed
    pair = await start_committed_session(committed, make_service)

    async with engine.connect() as blocker:
        await blocker.begin()
        await blocker.execute(
            text("SELECT 1 FROM refresh_tokens WHERE token_hash = :h FOR UPDATE"),
            {"h": hash_refresh_token(pair.refresh_token)},
        )

        task = asyncio.create_task(attempt_refresh(factory, make_service, pair.refresh_token))
        await asyncio.sleep(0.3)
        assert not task.done(), "rotation proceeded without waiting for the row lock"

        await blocker.rollback()

    result = await asyncio.wait_for(task, timeout=5)
    assert isinstance(result, TokenPair)


async def test_sequential_rotation_with_committed_data(
    committed: tuple[async_sessionmaker[AsyncSession], list[uuid.UUID]],
    make_service: ServiceFactory,
) -> None:
    factory, _ = committed
    pair = await start_committed_session(committed, make_service)

    for _ in range(3):
        result = await attempt_refresh(factory, make_service, pair.refresh_token)
        assert isinstance(result, TokenPair)
        pair = result


async def test_queued_refreshes_reread_state_after_waiting(
    committed: tuple[async_sessionmaker[AsyncSession], list[uuid.UUID]],
    make_service: ServiceFactory,
    engine: AsyncEngine,
) -> None:
    """Deterministic race: all attempts are queued behind a lock before any can proceed.

    Without a lock on the token row, every attempt reads the token as unused, then proceeds on
    that stale read once released (double rotation, or constraint errors surfacing as 500s).
    """
    factory, _ = committed
    pair = await start_committed_session(committed, make_service)

    async with engine.connect() as blocker:
        await blocker.begin()
        await blocker.execute(
            text("SELECT 1 FROM auth_sessions WHERE id = :id FOR UPDATE"),
            {"id": pair.session_id},
        )
        tasks = [
            asyncio.create_task(attempt_refresh(factory, make_service, pair.refresh_token))
            for _ in range(5)
        ]
        await asyncio.sleep(0.5)  # let every attempt reach its first lock wait
        assert not any(task.done() for task in tasks)
        await blocker.rollback()

    results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)

    unexpected = [r for r in results if not isinstance(r, TokenPair | InvalidRefreshTokenError)]
    assert unexpected == []
    assert sum(isinstance(r, TokenPair) for r in results) == 1


async def test_refresh_racing_a_logout_cannot_succeed(
    committed: tuple[async_sessionmaker[AsyncSession], list[uuid.UUID]],
    make_service: ServiceFactory,
    engine: AsyncEngine,
) -> None:
    """A logout in flight must win: refresh waits on the session row, then sees it revoked."""
    factory, _ = committed
    pair = await start_committed_session(committed, make_service)

    async with engine.connect() as logout:
        await logout.begin()
        await logout.execute(
            text(
                "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'logout' "
                "WHERE id = :id"
            ),
            {"id": pair.session_id},
        )
        task = asyncio.create_task(attempt_refresh(factory, make_service, pair.refresh_token))
        await asyncio.sleep(0.3)
        assert not task.done(), "refresh did not wait for the in-flight revocation"
        await logout.commit()

    assert isinstance(await asyncio.wait_for(task, timeout=5), InvalidRefreshTokenError)
