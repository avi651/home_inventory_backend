"""Provider-agnostic identity lookup and linking primitives (D1), reused by OAuth later."""

import logging
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.emails import InvalidEmailError
from app.models.user_identity import IdentityProvider, UserIdentity
from app.services.identity_service import (
    IdentityAlreadyLinkedError,
    IdentityService,
    InvalidSubjectError,
    ProviderAlreadyLinkedError,
    normalize_subject,
)
from tests.support.factories import create_user

FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
GOOGLE, APPLE, EMAIL = IdentityProvider.GOOGLE, IdentityProvider.APPLE, IdentityProvider.EMAIL


@pytest.fixture
def identities(db_session: AsyncSession) -> IdentityService:
    return IdentityService(db_session)


async def count_identities(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(UserIdentity))).scalar_one()


class TestNormalizeSubject:
    def test_email_subject_is_the_normalized_address(self) -> None:
        assert normalize_subject(EMAIL, "  Alice@EXAMPLE.com ") == "alice@example.com"

    def test_invalid_email_subject_is_rejected(self) -> None:
        with pytest.raises(InvalidEmailError):
            normalize_subject(EMAIL, "not-an-email")

    @pytest.mark.parametrize("provider", [GOOGLE, APPLE])
    def test_oauth_subject_is_opaque_and_case_sensitive(self, provider: IdentityProvider) -> None:
        assert normalize_subject(provider, "AbC.123_xyz") == "AbC.123_xyz"

    @pytest.mark.parametrize("provider", [GOOGLE, APPLE])
    @pytest.mark.parametrize("raw", ["", " ", " sub", "sub ", "s\x00b", "s\nb", "x" * 256])
    def test_malformed_oauth_subject_is_rejected(
        self, provider: IdentityProvider, raw: str
    ) -> None:
        with pytest.raises(InvalidSubjectError):
            normalize_subject(provider, raw)


class TestLink:
    async def test_links_email_identity_with_subject_equal_to_email(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session, is_guest=False)

        identity = await identities.link(
            user.id, EMAIL, "Alice@Example.com", password_hash=FAKE_HASH
        )

        assert (identity.user_id, identity.provider) == (user.id, EMAIL)
        assert identity.subject == identity.email == "alice@example.com"
        assert identity.password_hash == FAKE_HASH
        assert identity.email_verified is False

    async def test_links_oauth_identity_with_informational_email(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)

        identity = await identities.link(
            user.id, GOOGLE, "g-1", email="Gina@Example.com", email_verified=True
        )

        assert (identity.subject, identity.email, identity.email_verified) == (
            "g-1",
            "gina@example.com",
            True,
        )
        assert identity.password_hash is None

    async def test_different_providers_can_belong_to_the_same_user(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)

        await identities.link(user.id, EMAIL, "alice@example.com", password_hash=FAKE_HASH)
        await identities.link(user.id, GOOGLE, "g-1")
        await identities.link(user.id, APPLE, "a-1")

        linked = await identities.list_for_user(user.id)
        assert [i.provider for i in linked] == [EMAIL, GOOGLE, APPLE]

    @pytest.mark.parametrize(
        ("provider", "subject", "kwargs"),
        [
            (EMAIL, "alice@example.com", {"password_hash": FAKE_HASH}),
            (GOOGLE, "g-1", {}),
            (APPLE, "a-1", {}),
        ],
    )
    async def test_identity_of_another_user_cannot_be_linked(
        self,
        identities: IdentityService,
        db_session: AsyncSession,
        provider: IdentityProvider,
        subject: str,
        kwargs: dict[str, Any],
    ) -> None:
        owner = await create_user(db_session)
        attacker = await create_user(db_session)
        await identities.link(owner.id, provider, subject, **kwargs)

        with pytest.raises(IdentityAlreadyLinkedError):
            await identities.link(
                attacker.id, provider, subject.upper() if provider is EMAIL else subject, **kwargs
            )

        assert await identities.list_for_user(attacker.id) == []
        resolved = await identities.resolve(provider, subject)
        assert resolved is not None
        assert resolved.user_id == owner.id

    async def test_relinking_own_identity_is_a_conflict(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        await identities.link(user.id, GOOGLE, "g-1")

        with pytest.raises(IdentityAlreadyLinkedError):
            await identities.link(user.id, GOOGLE, "g-1")

    async def test_second_identity_for_same_provider_is_refused(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        await identities.link(user.id, GOOGLE, "g-1")

        with pytest.raises(ProviderAlreadyLinkedError):
            await identities.link(user.id, GOOGLE, "g-2")

    async def test_conflict_leaves_the_transaction_usable(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        """Only the failed link is undone (savepoint): earlier work in the transaction stays."""
        user = await create_user(db_session)
        await identities.link(user.id, GOOGLE, "g-1")
        before = await count_identities(db_session)

        with pytest.raises(IdentityAlreadyLinkedError):
            await identities.link(user.id, GOOGLE, "g-1")
        await identities.link(user.id, APPLE, "a-1")

        assert await count_identities(db_session) == before + 1

    async def test_email_identity_requires_a_password_hash(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)

        with pytest.raises(ValueError, match="password_hash"):
            await identities.link(user.id, EMAIL, "alice@example.com")

    @pytest.mark.parametrize("provider", [GOOGLE, APPLE])
    async def test_oauth_identity_never_stores_a_password_hash(
        self, identities: IdentityService, db_session: AsyncSession, provider: IdentityProvider
    ) -> None:
        user = await create_user(db_session)

        with pytest.raises(ValueError, match="password_hash"):
            await identities.link(user.id, provider, "sub-1", password_hash=FAKE_HASH)

    async def test_malformed_subject_is_rejected_before_the_database(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        before = await count_identities(db_session)

        with pytest.raises(InvalidSubjectError):
            await identities.link(user.id, GOOGLE, " ")

        assert await count_identities(db_session) == before


class TestResolve:
    async def test_finds_email_identity_by_any_spelling(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        await identities.link(user.id, EMAIL, "alice@example.com", password_hash=FAKE_HASH)

        found = await identities.resolve(EMAIL, "  ALICE@example.COM")

        assert found is not None
        assert found.user_id == user.id

    async def test_loads_the_owning_user_without_lazy_io(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        await identities.link(user.id, GOOGLE, "g-1")
        db_session.expunge_all()

        found = await identities.resolve(GOOGLE, "g-1")

        assert found is not None
        assert found.user.id == user.id
        assert [i.provider for i in found.user.identities] == [GOOGLE]

    async def test_unknown_identity_is_none(self, identities: IdentityService) -> None:
        assert await identities.resolve(GOOGLE, "nobody") is None

    async def test_lookup_is_scoped_to_the_provider(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        await identities.link(user.id, GOOGLE, "shared-sub")

        assert await identities.resolve(APPLE, "shared-sub") is None

    async def test_oauth_subject_lookup_is_case_sensitive(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        await identities.link(user.id, GOOGLE, "AbC")

        assert await identities.resolve(GOOGLE, "abc") is None

    async def test_informational_oauth_email_never_resolves_an_email_login(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        """No implicit linking (D1): a Google email is not a password login."""
        user = await create_user(db_session)
        await identities.link(user.id, GOOGLE, "g-1", email="gina@example.com")

        assert await identities.resolve(EMAIL, "gina@example.com") is None

    async def test_malformed_input_resolves_to_none(self, identities: IdentityService) -> None:
        assert await identities.resolve(EMAIL, "not-an-email") is None
        assert await identities.resolve(GOOGLE, "") is None


class TestOwnerScopedAccess:
    async def test_get_for_user_returns_own_identity(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        identity = await identities.link(user.id, GOOGLE, "g-1")

        found = await identities.get_for_user(user_id=user.id, identity_id=identity.id)

        assert found is not None
        assert found.id == identity.id

    async def test_cross_user_lookup_is_rejected(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        owner = await create_user(db_session)
        other = await create_user(db_session)
        identity = await identities.link(owner.id, GOOGLE, "g-1")

        assert await identities.get_for_user(user_id=other.id, identity_id=identity.id) is None
        assert await identities.list_for_user(other.id) == []

    async def test_list_for_user_only_returns_own_identities(
        self, identities: IdentityService, db_session: AsyncSession
    ) -> None:
        alice = await create_user(db_session)
        bob = await create_user(db_session)
        await identities.link(alice.id, GOOGLE, "g-alice")
        await identities.link(bob.id, GOOGLE, "g-bob")
        await identities.link(bob.id, APPLE, "a-bob")

        assert [i.subject for i in await identities.list_for_user(alice.id)] == ["g-alice"]


class TestNoLeaks:
    async def test_subjects_emails_and_hashes_are_never_logged(
        self,
        identities: IdentityService,
        db_session: AsyncSession,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        alice = await create_user(db_session)
        mallory = await create_user(db_session)

        await identities.link(alice.id, EMAIL, "secret.person@example.com", password_hash=FAKE_HASH)
        await identities.link(alice.id, GOOGLE, "g-secret-sub", email="g.secret@example.com")
        with pytest.raises(IdentityAlreadyLinkedError):
            await identities.link(mallory.id, GOOGLE, "g-secret-sub")
        await identities.resolve(GOOGLE, "g-secret-sub")
        await identities.resolve(EMAIL, "secret.person@example.com")

        logged = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
        for value in (
            "secret.person",
            "g-secret-sub",
            "g.secret",
            FAKE_HASH,
            "$argon2",
        ):
            assert value not in logged
