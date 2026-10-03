import logging
import uuid
from collections.abc import Awaitable
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.refresh_tokens import (
    REFRESH_TOKEN_PREFIX,
    generate_refresh_token,
    hash_refresh_token,
)
from app.core.tokens import AccessTokenService
from app.exceptions.errors import InvalidRefreshTokenError
from app.models.auth_session import AuthSession, SessionRevokeReason
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.services.session_service import SESSION_MAX_LIFETIME, SessionService, TokenPair
from tests.support.clock import FrozenClock
from tests.support.factories import create_user


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def access_tokens(test_settings: Settings, clock: FrozenClock) -> AccessTokenService:
    return AccessTokenService(test_settings, clock=clock)


@pytest.fixture
def service(
    db_session: AsyncSession,
    access_tokens: AccessTokenService,
    test_settings: Settings,
    clock: FrozenClock,
) -> SessionService:
    return SessionService(db_session, access_tokens, test_settings, clock=clock)


@pytest.fixture
async def user(db_session: AsyncSession) -> User:
    return await create_user(db_session)


async def assert_rejected(call: Awaitable[Any], *tokens: str) -> None:
    with pytest.raises(InvalidRefreshTokenError) as exc_info:
        await call
    error = exc_info.value
    assert str(error) == "Invalid refresh token"
    assert error.__cause__ is None
    assert error.__context__ is None or error.__suppress_context__
    for token in tokens:
        assert token not in str(error)
        assert token not in repr(error)


async def load_session(db: AsyncSession, session_id: uuid.UUID) -> AuthSession:
    auth_session = await db.get(AuthSession, session_id, populate_existing=True)
    assert auth_session is not None
    return auth_session


class TestStart:
    async def test_returns_token_pair(
        self, service: SessionService, access_tokens: AccessTokenService, user: User
    ) -> None:
        pair = await service.start(user.id)

        assert pair.refresh_token.startswith(REFRESH_TOKEN_PREFIX)
        assert pair.token_type == "bearer"
        assert pair.expires_in == 15 * 60
        claims = access_tokens.decode(pair.access_token)
        assert claims.user_id == user.id
        assert claims.session_id == pair.session_id

    async def test_session_expiry_is_absolute_cap(
        self, service: SessionService, db_session: AsyncSession, clock: FrozenClock, user: User
    ) -> None:
        pair = await service.start(user.id)

        auth_session = await load_session(db_session, pair.session_id)
        assert auth_session.user_id == user.id
        assert auth_session.expires_at == clock() + SESSION_MAX_LIFETIME

    async def test_each_login_is_a_separate_session(
        self, service: SessionService, user: User
    ) -> None:
        first, second = await service.start(user.id), await service.start(user.id)

        assert first.session_id != second.session_id


class TestRotation:
    async def test_refresh_issues_new_refresh_and_access_tokens(
        self, service: SessionService, access_tokens: AccessTokenService, user: User
    ) -> None:
        old = await service.start(user.id)

        new = await service.refresh(old.refresh_token)

        assert new.refresh_token != old.refresh_token
        assert new.access_token != old.access_token
        assert new.refresh_token.startswith(REFRESH_TOKEN_PREFIX)
        claims = access_tokens.decode(new.access_token)
        assert claims.user_id == user.id
        assert claims.session_id == old.session_id

    async def test_session_id_is_stable_across_rotations(
        self, service: SessionService, user: User
    ) -> None:
        pair = await service.start(user.id)
        session_id = pair.session_id

        for _ in range(5):
            pair = await service.refresh(pair.refresh_token)
            assert pair.session_id == session_id

    async def test_old_token_cannot_be_used_after_rotation(
        self, service: SessionService, user: User
    ) -> None:
        old = await service.start(user.id)
        await service.refresh(old.refresh_token)

        await assert_rejected(service.refresh(old.refresh_token), old.refresh_token)

    async def test_new_token_expiry_slides_but_never_exceeds_session(
        self, service: SessionService, db_session: AsyncSession, clock: FrozenClock, user: User
    ) -> None:
        pair = await service.start(user.id)
        # Refresh every 29 days (inside the 30-day idle window) up to day 87 of 90.
        for _ in range(3):
            clock.advance(timedelta(days=29))
            pair = await service.refresh(pair.refresh_token)

        stored = (
            await db_session.execute(
                select(RefreshToken).where(
                    RefreshToken.token_hash == hash_refresh_token(pair.refresh_token)
                )
            )
        ).scalar_one()
        auth_session = await load_session(db_session, pair.session_id)
        assert stored.expires_at == auth_session.expires_at

    async def test_records_last_refresh_time(
        self, service: SessionService, db_session: AsyncSession, clock: FrozenClock, user: User
    ) -> None:
        pair = await service.start(user.id)
        clock.advance(timedelta(hours=2))

        await service.refresh(pair.refresh_token)

        assert (await load_session(db_session, pair.session_id)).last_refreshed_at == clock()


class TestReuseDetection:
    async def test_reuse_revokes_the_entire_session(
        self, service: SessionService, db_session: AsyncSession, user: User
    ) -> None:
        old = await service.start(user.id)
        new = await service.refresh(old.refresh_token)

        await assert_rejected(service.refresh(old.refresh_token), old.refresh_token)

        # The legitimate holder's current token dies with the session (strict, D3).
        await assert_rejected(service.refresh(new.refresh_token), new.refresh_token)
        auth_session = await load_session(db_session, old.session_id)
        assert auth_session.revoked_reason is SessionRevokeReason.REUSE_DETECTED
        assert auth_session.revoked_at is not None

    async def test_reuse_goes_through_central_revoke(
        self, service: SessionService, user: User, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        old = await service.start(user.id)
        await service.refresh(old.refresh_token)
        calls: list[dict[str, Any]] = []
        original = service.revoke

        async def spy(**kwargs: Any) -> int:
            calls.append(kwargs)
            return await original(**kwargs)

        monkeypatch.setattr(service, "revoke", spy)

        await assert_rejected(service.refresh(old.refresh_token))

        assert calls == [
            {
                "user_id": user.id,
                "session_id": old.session_id,
                "reason": SessionRevokeReason.REUSE_DETECTED,
            }
        ]

    async def test_reuse_is_audited_without_the_token(
        self, service: SessionService, user: User, caplog: pytest.LogCaptureFixture
    ) -> None:
        old = await service.start(user.id)
        await service.refresh(old.refresh_token)
        caplog.set_level(logging.INFO)

        await assert_rejected(service.refresh(old.refresh_token))

        reuse = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING and "reuse detected" in r.getMessage()
        ]
        assert len(reuse) == 1
        assert str(old.session_id) in reuse[0].getMessage()
        assert old.refresh_token not in reuse[0].getMessage()


class TestRejection:
    async def test_revoked_session_cannot_refresh(
        self, service: SessionService, user: User
    ) -> None:
        pair = await service.start(user.id)

        await service.revoke(
            user_id=user.id, session_id=pair.session_id, reason=SessionRevokeReason.LOGOUT
        )

        await assert_rejected(service.refresh(pair.refresh_token), pair.refresh_token)

    async def test_refresh_token_is_valid_until_idle_expiry(
        self, service: SessionService, clock: FrozenClock, test_settings: Settings, user: User
    ) -> None:
        pair = await service.start(user.id)
        clock.advance(
            timedelta(days=test_settings.refresh_token_expire_days) - timedelta(seconds=1)
        )

        assert (await service.refresh(pair.refresh_token)).session_id == pair.session_id

    async def test_expired_refresh_token_is_rejected(
        self, service: SessionService, clock: FrozenClock, test_settings: Settings, user: User
    ) -> None:
        pair = await service.start(user.id)
        clock.advance(timedelta(days=test_settings.refresh_token_expire_days))

        await assert_rejected(service.refresh(pair.refresh_token), pair.refresh_token)

    async def test_session_cannot_outlive_absolute_lifetime(
        self, service: SessionService, clock: FrozenClock, user: User
    ) -> None:
        pair = await service.start(user.id)
        # Refresh every 20 days: never idle-expired, but the 90-day cap still ends the session.
        for _ in range(4):
            clock.advance(timedelta(days=20))
            pair = await service.refresh(pair.refresh_token)
        clock.advance(timedelta(days=20))

        await assert_rejected(service.refresh(pair.refresh_token), pair.refresh_token)

    async def test_shortened_session_expiry_applies_to_existing_tokens(
        self, service: SessionService, db_session: AsyncSession, clock: FrozenClock, user: User
    ) -> None:
        # e.g. a policy change or admin action shortens a session after tokens were issued.
        pair = await service.start(user.id)
        auth_session = await load_session(db_session, pair.session_id)
        auth_session.expires_at = clock() - timedelta(seconds=1)
        await db_session.flush()

        await assert_rejected(service.refresh(pair.refresh_token), pair.refresh_token)

    async def test_inactive_user_cannot_refresh(
        self, service: SessionService, db_session: AsyncSession, user: User
    ) -> None:
        pair = await service.start(user.id)
        user.is_active = False
        await db_session.flush()

        await assert_rejected(service.refresh(pair.refresh_token), pair.refresh_token)

    async def test_deleted_user_cannot_refresh(
        self, service: SessionService, db_session: AsyncSession, user: User
    ) -> None:
        pair = await service.start(user.id)
        await db_session.delete(user)
        await db_session.flush()

        await assert_rejected(service.refresh(pair.refresh_token), pair.refresh_token)

    @pytest.mark.parametrize(
        "token",
        [
            "",
            "garbage",
            REFRESH_TOKEN_PREFIX,
            REFRESH_TOKEN_PREFIX + "!" * 43,
            "a" * 10_000,
            "'; DROP TABLE refresh_tokens; --",
        ],
    )
    async def test_malformed_tokens_are_rejected(self, service: SessionService, token: str) -> None:
        await assert_rejected(service.refresh(token))

    async def test_malformed_tokens_never_reach_the_database(
        self, service: SessionService, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def must_not_query(*_: object, **__: object) -> None:
            raise AssertionError("malformed tokens must be rejected before any query")

        monkeypatch.setattr(db_session, "execute", must_not_query)
        monkeypatch.setattr(db_session, "scalar", must_not_query)

        await assert_rejected(service.refresh("not-a-refresh-token"))

    async def test_random_well_formed_token_is_rejected(self, service: SessionService) -> None:
        never_issued = generate_refresh_token()

        await assert_rejected(service.refresh(never_issued), never_issued)

    async def test_almost_correct_token_is_rejected(
        self, service: SessionService, user: User
    ) -> None:
        pair = await service.start(user.id)
        last = pair.refresh_token[-1]
        wrong = pair.refresh_token[:-1] + ("A" if last != "A" else "B")

        await assert_rejected(service.refresh(wrong), wrong)

    async def test_access_token_is_not_accepted_as_refresh_token(
        self, service: SessionService, user: User
    ) -> None:
        pair = await service.start(user.id)

        await assert_rejected(service.refresh(pair.access_token), pair.access_token)

    async def test_failures_are_indistinguishable(
        self, service: SessionService, db_session: AsyncSession, clock: FrozenClock, user: User
    ) -> None:
        """Unknown, reused, revoked and expired tokens all produce the same error."""
        reused = await service.start(user.id)
        await service.refresh(reused.refresh_token)
        revoked = await service.start(user.id)
        await service.revoke(
            user_id=user.id, session_id=revoked.session_id, reason=SessionRevokeReason.LOGOUT
        )

        errors = []
        for token in (generate_refresh_token(), reused.refresh_token, revoked.refresh_token):
            with pytest.raises(InvalidRefreshTokenError) as exc_info:
                await service.refresh(token)
            errors.append((type(exc_info.value), str(exc_info.value), exc_info.value.args))

        assert len(set(errors)) == 1


class TestStorage:
    async def test_only_the_hash_is_stored(
        self, service: SessionService, db_session: AsyncSession, user: User
    ) -> None:
        first = await service.start(user.id)
        second = await service.refresh(first.refresh_token)

        rows = (
            await db_session.execute(
                text(
                    "SELECT rt::text FROM refresh_tokens rt "
                    "JOIN auth_sessions s ON s.id = rt.session_id WHERE s.user_id = :user_id"
                ),
                {"user_id": user.id},
            )
        ).scalars()
        dumped = "\n".join(rows)

        for raw in (first.refresh_token, second.refresh_token):
            assert raw not in dumped
            assert raw.removeprefix(REFRESH_TOKEN_PREFIX) not in dumped
            assert hash_refresh_token(raw) in dumped

    async def test_rotation_keeps_exactly_one_active_token(
        self, service: SessionService, db_session: AsyncSession, user: User
    ) -> None:
        pair = await service.start(user.id)
        for _ in range(3):
            pair = await service.refresh(pair.refresh_token)

        tokens = (
            await db_session.execute(
                select(RefreshToken).where(RefreshToken.session_id == pair.session_id)
            )
        ).scalars()
        states = [token.used_at is None for token in tokens]
        assert states.count(True) == 1
        assert states.count(False) == 3


class TestIsolationAndOwnership:
    async def test_reuse_in_one_session_does_not_affect_another(
        self, service: SessionService, user: User
    ) -> None:
        phone, tablet = await service.start(user.id), await service.start(user.id)
        await service.refresh(phone.refresh_token)
        await assert_rejected(service.refresh(phone.refresh_token))

        assert (await service.refresh(tablet.refresh_token)).session_id == tablet.session_id

    async def test_cannot_revoke_another_users_session(
        self, service: SessionService, db_session: AsyncSession, user: User
    ) -> None:
        victim = await service.start(user.id)
        attacker = await create_user(db_session)

        revoked = await service.revoke(
            user_id=attacker.id,
            session_id=victim.session_id,
            reason=SessionRevokeReason.USER_REVOKED,
        )

        assert revoked == 0
        assert (await service.refresh(victim.refresh_token)).session_id == victim.session_id

    async def test_revoke_all_only_affects_that_user(
        self, service: SessionService, db_session: AsyncSession, user: User
    ) -> None:
        mine = [await service.start(user.id) for _ in range(3)]
        other_user = await create_user(db_session)
        theirs = await service.start(other_user.id)

        revoked = await service.revoke(user_id=user.id, reason=SessionRevokeReason.LOGOUT_ALL)

        assert revoked == 3
        for pair in mine:
            await assert_rejected(service.refresh(pair.refresh_token))
        assert (await service.refresh(theirs.refresh_token)).session_id == theirs.session_id

    async def test_revoking_twice_is_idempotent_and_keeps_first_reason(
        self, service: SessionService, db_session: AsyncSession, user: User
    ) -> None:
        pair = await service.start(user.id)
        kwargs = {"user_id": user.id, "session_id": pair.session_id}

        assert await service.revoke(**kwargs, reason=SessionRevokeReason.LOGOUT) == 1
        assert await service.revoke(**kwargs, reason=SessionRevokeReason.LOGOUT_ALL) == 0
        auth_session = await load_session(db_session, pair.session_id)
        assert auth_session.revoked_reason is SessionRevokeReason.LOGOUT

    async def test_refresh_returns_tokens_only_for_the_owning_user(
        self, service: SessionService, access_tokens: AccessTokenService, db_session: AsyncSession
    ) -> None:
        alice, bob = await create_user(db_session), await create_user(db_session)
        alice_pair, bob_pair = await service.start(alice.id), await service.start(bob.id)

        assert (
            access_tokens.decode(
                (await service.refresh(alice_pair.refresh_token)).access_token
            ).user_id
            == alice.id
        )
        assert (
            access_tokens.decode(
                (await service.refresh(bob_pair.refresh_token)).access_token
            ).user_id
            == bob.id
        )


class TestTransactionSafety:
    async def test_failed_rotation_rolls_back_and_old_token_stays_valid(
        self,
        service: SessionService,
        db_session: AsyncSession,
        user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pair = await service.start(user.id)

        def explode(**_: object) -> None:
            raise RuntimeError("simulated failure after the old token was marked used")

        with monkeypatch.context() as patch:
            patch.setattr(service._access_tokens, "issue", explode)
            with pytest.raises(RuntimeError):
                await service.refresh(pair.refresh_token)

        # Nothing half-applied: the old token was not consumed and no new token exists.
        assert (await service.refresh(pair.refresh_token)).session_id == pair.session_id

    async def test_failed_rotation_does_not_mark_token_used(
        self,
        service: SessionService,
        db_session: AsyncSession,
        user: User,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pair = await service.start(user.id)

        async def fail_commit() -> None:
            raise RuntimeError("simulated commit failure")

        with monkeypatch.context() as patch:
            patch.setattr(db_session, "commit", fail_commit)
            with pytest.raises(RuntimeError):
                await service.refresh(pair.refresh_token)

        stored = (
            await db_session.execute(
                select(RefreshToken).where(
                    RefreshToken.token_hash == hash_refresh_token(pair.refresh_token)
                )
            )
        ).scalar_one()
        assert stored.used_at is None


class TestLogging:
    async def test_tokens_never_logged(
        self, service: SessionService, user: User, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        first = await service.start(user.id)
        second = await service.refresh(first.refresh_token)
        await assert_rejected(service.refresh(first.refresh_token))  # reuse path logs a warning
        await assert_rejected(service.refresh(generate_refresh_token()))

        logged = "\n".join(
            f"{record.getMessage()} {record.exc_text or ''}" for record in caplog.records
        )
        for pair in (first, second):
            assert pair.refresh_token not in logged
            assert pair.refresh_token.removeprefix(REFRESH_TOKEN_PREFIX) not in logged
            assert pair.access_token not in logged
            assert hash_refresh_token(pair.refresh_token) not in logged


def test_token_pair_repr_hides_tokens() -> None:
    pair = TokenPair(
        access_token="eyJ.secret.access",
        refresh_token=generate_refresh_token(),
        expires_in=900,
        session_id=uuid.uuid7(),
    )

    assert pair.access_token not in repr(pair)
    assert pair.refresh_token not in repr(pair)
