import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.refresh_tokens import generate_refresh_token, hash_refresh_token
from app.models.auth_session import AuthSession, SessionRevokeReason
from app.models.refresh_token import RefreshToken
from app.models.user import User
from tests.support.factories import create_user

LATER = datetime(2030, 1, 1, tzinfo=UTC)


async def create_session(db: AsyncSession, user: User) -> AuthSession:
    auth_session = AuthSession(user_id=user.id, expires_at=LATER)
    db.add(auth_session)
    await db.flush()
    await db.refresh(auth_session)
    return auth_session


def make_token(auth_session: AuthSession, **overrides: object) -> RefreshToken:
    values: dict[str, object] = {
        "session_id": auth_session.id,
        "token_hash": hash_refresh_token(generate_refresh_token()),
        "expires_at": LATER,
    }
    values.update(overrides)
    return RefreshToken(**values)


async def assert_rejected(db: AsyncSession, obj: object, constraint: str) -> None:
    db.add(obj)
    with pytest.raises(IntegrityError, match=constraint):
        await db.flush()
    await db.rollback()


class TestAuthSession:
    async def test_defaults(self, db_session: AsyncSession) -> None:
        auth_session = await create_session(db_session, await create_user(db_session))

        assert auth_session.id.version == 7
        assert auth_session.revoked_at is None
        assert auth_session.revoked_reason is None
        assert auth_session.created_at.tzinfo is not None

    @pytest.mark.parametrize(
        "overrides",
        [
            {"revoked_at": LATER},
            {"revoked_reason": SessionRevokeReason.LOGOUT},
        ],
    )
    async def test_revocation_fields_are_set_together(
        self, db_session: AsyncSession, overrides: dict[str, object]
    ) -> None:
        user = await create_user(db_session)

        await assert_rejected(
            db_session,
            AuthSession(user_id=user.id, expires_at=LATER, **overrides),
            "ck_auth_sessions_revocation_consistent",
        )

    async def test_requires_existing_user(self, db_session: AsyncSession) -> None:
        await assert_rejected(
            db_session,
            AuthSession(user_id=uuid.uuid7(), expires_at=LATER),
            "fk_auth_sessions_user_id_users",
        )


class TestRefreshToken:
    @pytest.mark.parametrize(
        "bad_hash",
        [
            generate_refresh_token(),  # plaintext token must be impossible to store
            "A" * 64,  # uppercase hex
            "a" * 63,
            "g" * 64,
        ],
    )
    async def test_only_sha256_hex_can_be_stored(
        self, db_session: AsyncSession, bad_hash: str
    ) -> None:
        auth_session = await create_session(db_session, await create_user(db_session))

        await assert_rejected(
            db_session,
            make_token(auth_session, token_hash=bad_hash),
            "ck_refresh_tokens_token_hash_format",
        )

    async def test_hash_is_unique(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)
        first, second = (
            await create_session(db_session, user),
            await create_session(db_session, user),
        )
        digest = hash_refresh_token(generate_refresh_token())
        db_session.add(make_token(first, token_hash=digest))
        await db_session.flush()

        await assert_rejected(
            db_session, make_token(second, token_hash=digest), "uq_refresh_tokens_token_hash"
        )

    async def test_only_one_unused_token_per_session(self, db_session: AsyncSession) -> None:
        auth_session = await create_session(db_session, await create_user(db_session))
        db_session.add(make_token(auth_session))
        await db_session.flush()

        await assert_rejected(
            db_session, make_token(auth_session), "uq_refresh_tokens_one_active_per_session"
        )

    async def test_used_tokens_do_not_count_as_active(self, db_session: AsyncSession) -> None:
        auth_session = await create_session(db_session, await create_user(db_session))
        db_session.add(make_token(auth_session, used_at=LATER))
        db_session.add(make_token(auth_session, used_at=LATER))
        db_session.add(make_token(auth_session))

        await db_session.flush()

    async def test_requires_existing_session(self, db_session: AsyncSession) -> None:
        await assert_rejected(
            db_session,
            RefreshToken(
                session_id=uuid.uuid7(),
                token_hash=hash_refresh_token(generate_refresh_token()),
                expires_at=LATER,
            ),
            "fk_refresh_tokens_session_id_auth_sessions",
        )


async def test_deleting_user_cascades_to_sessions_and_tokens(db_session: AsyncSession) -> None:
    user = await create_user(db_session)
    auth_session = await create_session(db_session, user)
    db_session.add(make_token(auth_session))
    await db_session.flush()

    await db_session.execute(delete(User).where(User.id == user.id))

    remaining_sessions = select(func.count()).where(AuthSession.user_id == user.id)
    remaining_tokens = select(func.count()).where(RefreshToken.session_id == auth_session.id)
    assert (await db_session.execute(remaining_sessions)).scalar_one() == 0
    assert (await db_session.execute(remaining_tokens)).scalar_one() == 0


async def test_expiry_is_timezone_aware(db_session: AsyncSession) -> None:
    auth_session = await create_session(db_session, await create_user(db_session))
    token = make_token(auth_session, expires_at=LATER + timedelta(days=1))
    db_session.add(token)
    await db_session.flush()
    await db_session.refresh(token)

    assert token.expires_at.tzinfo is not None
