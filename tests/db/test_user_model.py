from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import AuthProvider, User

FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"


def email_user(**overrides: Any) -> User:
    values: dict[str, Any] = {
        "auth_provider": AuthProvider.EMAIL,
        "email": "alice@example.com",
        "password_hash": FAKE_HASH,
    }
    values.update(overrides)
    return User(**values)


async def save(session: AsyncSession, user: User) -> User:
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return user


async def assert_rejected(session: AsyncSession, user: User, constraint: str) -> None:
    session.add(user)
    with pytest.raises(IntegrityError, match=constraint):
        await session.flush()
    await session.rollback()


class TestIdentityAndTimestamps:
    async def test_primary_key_is_uuid7(self, db_session: AsyncSession) -> None:
        user = await save(db_session, email_user())

        assert user.id.version == 7

    async def test_ids_are_time_ordered(self, db_session: AsyncSession) -> None:
        first = await save(db_session, email_user(email="a@example.com"))
        second = await save(db_session, email_user(email="b@example.com"))

        assert first.id < second.id

    async def test_timestamps_are_set_by_database(self, db_session: AsyncSession) -> None:
        user = await save(db_session, email_user())

        assert user.created_at.tzinfo is not None
        assert user.updated_at >= user.created_at
        db_now = (await db_session.execute(select(func.clock_timestamp()))).scalar_one()
        assert db_now - user.created_at < timedelta(minutes=1)

    async def test_updated_at_changes_on_update(self, db_session: AsyncSession) -> None:
        user = await save(db_session, email_user())
        created, before = user.created_at, user.updated_at

        user.is_active = False
        await db_session.flush()
        await db_session.refresh(user)

        assert user.updated_at > before
        assert user.created_at == created

    async def test_new_users_are_active_by_default(self, db_session: AsyncSession) -> None:
        assert (await save(db_session, email_user())).is_active is True


class TestEmail:
    async def test_duplicate_email_is_rejected(self, db_session: AsyncSession) -> None:
        await save(db_session, email_user())

        await assert_rejected(db_session, email_user(), "uq_users_email")

    async def test_mixed_case_email_is_rejected_by_database(self, db_session: AsyncSession) -> None:
        # The service layer normalises; the DB guarantees case-variant duplicates cannot exist.
        await assert_rejected(
            db_session, email_user(email="Alice@Example.com"), "ck_users_email_lowercase"
        )

    async def test_email_without_at_sign_is_rejected(self, db_session: AsyncSession) -> None:
        await assert_rejected(db_session, email_user(email="not-an-email"), "ck_users_email_format")

    async def test_overlong_email_is_rejected(self, db_session: AsyncSession) -> None:
        overlong = "a" * 310 + "@example.com"

        session_user = email_user(email=overlong)
        db_session.add(session_user)
        with pytest.raises(DataError, match="too long"):
            await db_session.flush()
        await db_session.rollback()


class TestProviderRules:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"email": None},
            {"password_hash": None},
            {"provider_subject": "should-not-be-set"},
        ],
    )
    async def test_email_provider_rules(
        self, db_session: AsyncSession, overrides: dict[str, Any]
    ) -> None:
        await assert_rejected(db_session, email_user(**overrides), "ck_users_auth_provider_fields")

    @pytest.mark.parametrize("provider", [AuthProvider.GOOGLE, AuthProvider.APPLE])
    async def test_oauth_user_valid_without_password(
        self, db_session: AsyncSession, provider: AuthProvider
    ) -> None:
        user = await save(
            db_session, User(auth_provider=provider, provider_subject="sub-123", email=None)
        )

        assert user.password_hash is None

    @pytest.mark.parametrize("provider", [AuthProvider.GOOGLE, AuthProvider.APPLE])
    @pytest.mark.parametrize(
        "overrides",
        [
            {"provider_subject": None},
            {"provider_subject": ""},
            {"provider_subject": "sub-1", "password_hash": FAKE_HASH},
        ],
    )
    async def test_oauth_provider_rules(
        self, db_session: AsyncSession, provider: AuthProvider, overrides: dict[str, Any]
    ) -> None:
        await assert_rejected(
            db_session,
            User(auth_provider=provider, **overrides),
            "ck_users_auth_provider_fields",
        )

    async def test_guest_user_has_no_credentials(self, db_session: AsyncSession) -> None:
        user = await save(db_session, User(auth_provider=AuthProvider.GUEST))

        assert (user.email, user.password_hash, user.provider_subject) == (None, None, None)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"email": "guest@example.com"},
            {"password_hash": FAKE_HASH},
            {"provider_subject": "sub-1"},
        ],
    )
    async def test_guest_provider_rules(
        self, db_session: AsyncSession, overrides: dict[str, Any]
    ) -> None:
        await assert_rejected(
            db_session,
            User(auth_provider=AuthProvider.GUEST, **overrides),
            "ck_users_auth_provider_fields",
        )

    async def test_provider_subject_unique_per_provider(self, db_session: AsyncSession) -> None:
        await save(db_session, User(auth_provider=AuthProvider.GOOGLE, provider_subject="s-1"))

        await assert_rejected(
            db_session,
            User(auth_provider=AuthProvider.GOOGLE, provider_subject="s-1"),
            "uq_users_provider_subject",
        )

    async def test_same_subject_allowed_across_providers(self, db_session: AsyncSession) -> None:
        await save(db_session, User(auth_provider=AuthProvider.GOOGLE, provider_subject="s-1"))

        user = await save(
            db_session, User(auth_provider=AuthProvider.APPLE, provider_subject="s-1")
        )

        assert user.id is not None

    async def test_unknown_provider_is_rejected(self, db_session: AsyncSession) -> None:
        with pytest.raises(DataError, match="invalid input value for enum"):
            await db_session.execute(
                text("INSERT INTO users (id, auth_provider) VALUES (gen_random_uuid(), 'facebook')")
            )
        await db_session.rollback()


class TestSecurity:
    async def test_sql_injection_payload_is_stored_as_data(self, db_session: AsyncSession) -> None:
        payload = "x'); drop table users; --@example.com"
        await save(db_session, email_user(email=payload))

        found = (await db_session.execute(select(User).where(User.email == payload))).scalar_one()

        assert found.email == payload
        assert await db_session.run_sync(lambda s: inspect(s.connection()).has_table("users"))

    async def test_repr_never_includes_password_hash(self, db_session: AsyncSession) -> None:
        user = await save(db_session, email_user())

        assert FAKE_HASH not in repr(user)
        assert FAKE_HASH not in str(user)
