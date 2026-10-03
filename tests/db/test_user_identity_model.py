"""Database-level guarantees for user_identities (D1). Moved here from the Phase 1 users tests."""

import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.user_identity import IdentityProvider, UserIdentity
from tests.support.factories import create_user

FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"


def email_identity(user: User, **overrides: Any) -> UserIdentity:
    email = overrides.pop("email", "alice@example.com")
    values: dict[str, Any] = {
        "user_id": user.id,
        "provider": IdentityProvider.EMAIL,
        "subject": email,
        "email": email,
        "password_hash": FAKE_HASH,
    }
    values.update(overrides)
    return UserIdentity(**values)


def oauth_identity(user: User, provider: IdentityProvider, **overrides: Any) -> UserIdentity:
    values: dict[str, Any] = {"user_id": user.id, "provider": provider, "subject": "sub-123"}
    values.update(overrides)
    return UserIdentity(**values)


async def save(db: AsyncSession, identity: UserIdentity) -> UserIdentity:
    db.add(identity)
    await db.flush()
    await db.refresh(identity)
    return identity


async def assert_rejected(db: AsyncSession, identity: UserIdentity, constraint: str) -> None:
    db.add(identity)
    with pytest.raises(IntegrityError, match=constraint):
        await db.flush()
    await db.rollback()


class TestIdentityAndTimestamps:
    async def test_primary_key_is_uuid7_and_timestamps_set_by_db(
        self, db_session: AsyncSession
    ) -> None:
        identity = await save(db_session, email_identity(await create_user(db_session)))

        assert identity.id.version == 7
        assert identity.created_at.tzinfo is not None
        assert identity.updated_at >= identity.created_at
        db_now = (await db_session.execute(select(func.clock_timestamp()))).scalar_one()
        assert db_now - identity.created_at < timedelta(minutes=1)

    async def test_defaults(self, db_session: AsyncSession) -> None:
        identity = await save(db_session, email_identity(await create_user(db_session)))

        assert identity.email_verified is False
        assert identity.last_used_at is None

    async def test_user_id_is_required(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)

        await assert_rejected(db_session, email_identity(user, user_id=None), "user_id")

    async def test_user_must_exist(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)

        await assert_rejected(
            db_session,
            email_identity(user, user_id=uuid.uuid7()),
            "fk_user_identities_user_id_users",
        )


class TestUniqueness:
    async def test_duplicate_email_identity_is_rejected(self, db_session: AsyncSession) -> None:
        await save(db_session, email_identity(await create_user(db_session)))

        await assert_rejected(
            db_session,
            email_identity(await create_user(db_session)),
            "uq_user_identities_provider_subject",
        )

    @pytest.mark.parametrize("provider", [IdentityProvider.GOOGLE, IdentityProvider.APPLE])
    async def test_same_provider_subject_cannot_belong_to_two_users(
        self, db_session: AsyncSession, provider: IdentityProvider
    ) -> None:
        await save(db_session, oauth_identity(await create_user(db_session), provider))

        await assert_rejected(
            db_session,
            oauth_identity(await create_user(db_session), provider),
            "uq_user_identities_provider_subject",
        )

    async def test_same_identity_cannot_be_linked_twice_to_one_user(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        await save(db_session, oauth_identity(user, IdentityProvider.GOOGLE))

        await assert_rejected(
            db_session,
            oauth_identity(user, IdentityProvider.GOOGLE),
            "uq_user_identities_provider_subject",
        )

    async def test_one_identity_per_provider_per_user(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)
        await save(db_session, oauth_identity(user, IdentityProvider.GOOGLE, subject="g-1"))

        await assert_rejected(
            db_session,
            oauth_identity(user, IdentityProvider.GOOGLE, subject="g-2"),
            "uq_user_identities_user_id_provider",
        )

    async def test_different_providers_can_belong_to_the_same_user(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)

        for identity in (
            email_identity(user),
            oauth_identity(user, IdentityProvider.GOOGLE),
            oauth_identity(user, IdentityProvider.APPLE),
        ):
            await save(db_session, identity)

        count = (
            await db_session.execute(select(func.count()).where(UserIdentity.user_id == user.id))
        ).scalar_one()
        assert count == 3

    async def test_same_subject_allowed_across_providers(self, db_session: AsyncSession) -> None:
        await save(
            db_session, oauth_identity(await create_user(db_session), IdentityProvider.GOOGLE)
        )

        identity = await save(
            db_session, oauth_identity(await create_user(db_session), IdentityProvider.APPLE)
        )

        assert identity.id is not None

    async def test_oauth_email_may_match_another_users_email_identity(
        self, db_session: AsyncSession
    ) -> None:
        """Informational email on Google/Apple never collides: no implicit linking (D1)."""
        await save(db_session, email_identity(await create_user(db_session)))

        identity = await save(
            db_session,
            oauth_identity(
                await create_user(db_session),
                IdentityProvider.GOOGLE,
                email="alice@example.com",
            ),
        )

        assert identity.email == "alice@example.com"


class TestEmailRules:
    async def test_mixed_case_email_is_rejected_by_database(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)

        await assert_rejected(
            db_session,
            email_identity(user, email="Alice@Example.com"),
            "ck_user_identities_email_lowercase",
        )

    async def test_email_without_at_sign_is_rejected(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)

        await assert_rejected(
            db_session,
            email_identity(user, email="not-an-email"),
            "ck_user_identities_email_format",
        )

    async def test_overlong_email_is_rejected(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)
        db_session.add(email_identity(user, email="a" * 310 + "@example.com"))

        with pytest.raises(DataError, match="too long"):
            await db_session.flush()
        await db_session.rollback()


class TestProviderRules:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"email": None, "subject": "alice@example.com"},
            {"subject": "someone-else@example.com"},
            {"password_hash": None},
        ],
    )
    async def test_email_provider_rules(
        self, db_session: AsyncSession, overrides: dict[str, Any]
    ) -> None:
        user = await create_user(db_session)

        await assert_rejected(
            db_session, email_identity(user, **overrides), "ck_user_identities_provider_fields"
        )

    @pytest.mark.parametrize("provider", [IdentityProvider.GOOGLE, IdentityProvider.APPLE])
    async def test_oauth_identity_valid_without_password_or_email(
        self, db_session: AsyncSession, provider: IdentityProvider
    ) -> None:
        identity = await save(db_session, oauth_identity(await create_user(db_session), provider))

        assert (identity.password_hash, identity.email) == (None, None)

    @pytest.mark.parametrize("provider", [IdentityProvider.GOOGLE, IdentityProvider.APPLE])
    @pytest.mark.parametrize(
        "overrides",
        [{"subject": ""}, {"password_hash": FAKE_HASH}],
    )
    async def test_oauth_provider_rules(
        self, db_session: AsyncSession, provider: IdentityProvider, overrides: dict[str, Any]
    ) -> None:
        user = await create_user(db_session)

        await assert_rejected(
            db_session,
            oauth_identity(user, provider, **overrides),
            "ck_user_identities_provider_fields",
        )

    async def test_subject_is_required(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)

        await assert_rejected(
            db_session, oauth_identity(user, IdentityProvider.GOOGLE, subject=None), "subject"
        )

    @pytest.mark.parametrize("provider", ["guest", "facebook"])
    async def test_unknown_provider_is_rejected(
        self, db_session: AsyncSession, provider: str
    ) -> None:
        """Guests are users.is_guest with no identity row (ARCHITECTURE.md §3), not a provider."""
        user = await create_user(db_session)

        with pytest.raises(DataError, match="invalid input value for enum"):
            await db_session.execute(
                text(
                    "INSERT INTO user_identities (id, user_id, provider, subject) "
                    "VALUES (gen_random_uuid(), :user_id, :provider, 'x')"
                ),
                {"user_id": user.id, "provider": provider},
            )
        await db_session.rollback()


class TestLifecycle:
    async def test_deleting_a_user_deletes_their_identities(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)
        other = await create_user(db_session)
        await save(db_session, email_identity(user))
        await save(db_session, oauth_identity(user, IdentityProvider.GOOGLE))
        kept = await save(db_session, oauth_identity(other, IdentityProvider.APPLE))

        await db_session.execute(text("DELETE FROM users WHERE id = :id"), {"id": user.id})

        remaining = (
            (
                await db_session.execute(
                    select(UserIdentity.id).where(UserIdentity.user_id.in_([user.id, other.id]))
                )
            )
            .scalars()
            .all()
        )
        assert remaining == [kept.id]


class TestSecurity:
    async def test_sql_injection_payload_is_stored_as_data(self, db_session: AsyncSession) -> None:
        payload = "x'); drop table user_identities; --@example.com"
        await save(db_session, email_identity(await create_user(db_session), email=payload))

        found = (
            await db_session.execute(select(UserIdentity).where(UserIdentity.subject == payload))
        ).scalar_one()

        assert found.email == payload
        assert await db_session.run_sync(
            lambda s: inspect(s.connection()).has_table("user_identities")
        )

    async def test_repr_never_includes_secrets_or_pii(self, db_session: AsyncSession) -> None:
        identity = await save(db_session, email_identity(await create_user(db_session)))
        google = await save(
            db_session,
            oauth_identity(
                await create_user(db_session), IdentityProvider.GOOGLE, subject="g-secret-sub"
            ),
        )

        for text_form in (repr(identity), str(identity), repr(google)):
            assert FAKE_HASH not in text_form
            assert "alice@example.com" not in text_form
            assert "g-secret-sub" not in text_form
