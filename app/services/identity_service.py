"""Provider-agnostic sign-in identities (D1): the one place that normalizes, finds and links them.

Email/password uses it today; Google/Apple sign-in will resolve and link through the same calls.
Logs carry ids and provider names only: never subjects, emails or password hashes.
"""

import logging
import re
import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.emails import InvalidEmailError, normalize_email
from app.models.user_identity import IdentityProvider, UserIdentity
from app.repositories.identity_repository import IdentityRepository

logger = logging.getLogger(__name__)

# OIDC `sub`: at most 255 ASCII chars (OIDC Core 2), compared exactly and case-sensitively.
# Visible ASCII only, so look-alike or whitespace-padded subjects cannot form a second identity.
_OAUTH_SUBJECT = re.compile(r"[\x21-\x7e]{1,255}")

_PROVIDER_SUBJECT_CONSTRAINT = "uq_user_identities_provider_subject"
_USER_PROVIDER_CONSTRAINT = "uq_user_identities_user_id_provider"


class InvalidSubjectError(ValueError):
    def __init__(self) -> None:
        super().__init__("invalid identity subject")


class IdentityAlreadyLinkedError(Exception):
    """This (provider, subject) already belongs to a user. Deliberately does not say which."""


class ProviderAlreadyLinkedError(Exception):
    """The user already has an identity for this provider."""


def normalize_subject(provider: IdentityProvider, raw: str) -> str:
    """Canonical subject per provider: the normalized address for email, the exact `sub` else."""
    if provider is IdentityProvider.EMAIL:
        return normalize_email(raw)
    if not _OAUTH_SUBJECT.fullmatch(raw):
        raise InvalidSubjectError
    return raw


def violated_constraint(exc: IntegrityError) -> str | None:
    diag = getattr(exc.orig, "diag", None)
    return getattr(diag, "constraint_name", None)


class IdentityService:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._identities = IdentityRepository(db)

    async def resolve(self, provider: IdentityProvider, subject: str) -> UserIdentity | None:
        """The identity (with its user loaded) for a sign-in, or None. Never matches by email
        across providers: a Google email does not resolve an email/password login (D1)."""
        try:
            subject = normalize_subject(provider, subject)
        except ValueError:
            return None
        return await self._identities.get_by_provider_subject(provider, subject)

    async def get_for_user(
        self, *, user_id: uuid.UUID, identity_id: uuid.UUID
    ) -> UserIdentity | None:
        return await self._identities.get_for_user(user_id=user_id, identity_id=identity_id)

    async def list_for_user(self, user_id: uuid.UUID) -> list[UserIdentity]:
        return await self._identities.list_for_user(user_id)

    async def link(
        self,
        user_id: uuid.UUID,
        provider: IdentityProvider,
        subject: str,
        *,
        email: str | None = None,
        email_verified: bool = False,
        password_hash: str | None = None,
    ) -> UserIdentity:
        """Attach a sign-in identity to user_id. Does not commit.

        The caller must already have authorized acting for user_id: linking is never implied by
        a matching email (D1). Uniqueness is decided by the database constraints, not a prior
        SELECT, so concurrent links of the same identity cannot both succeed.
        """
        if (provider is IdentityProvider.EMAIL) != (password_hash is not None):
            raise ValueError(
                "password_hash is required for email identities and forbidden otherwise"
            )
        subject = normalize_subject(provider, subject)
        if provider is IdentityProvider.EMAIL:
            email = subject
        elif email is not None:
            email = _informational_email(email)

        identity = UserIdentity(
            user_id=user_id,
            provider=provider,
            subject=subject,
            email=email,
            email_verified=email_verified,
            password_hash=password_hash,
        )
        try:
            # Savepoint: a conflict undoes only this link, not the caller's transaction.
            async with self._db.begin_nested():
                await self._identities.add(identity)
        except IntegrityError as exc:
            constraint = violated_constraint(exc)
            if constraint == _PROVIDER_SUBJECT_CONSTRAINT:
                logger.info(
                    "identity link refused (already linked) user_id=%s provider=%s",
                    user_id,
                    provider.value,
                )
                raise IdentityAlreadyLinkedError from None
            if constraint == _USER_PROVIDER_CONSTRAINT:
                logger.info(
                    "identity link refused (provider taken) user_id=%s provider=%s",
                    user_id,
                    provider.value,
                )
                raise ProviderAlreadyLinkedError from None
            raise
        logger.info(
            "identity linked user_id=%s provider=%s identity_id=%s",
            user_id,
            provider.value,
            identity.id,
        )
        return identity


def _informational_email(raw: str) -> str | None:
    # Provider-reported email is display data only; an address we cannot normalize is dropped
    # rather than failing the sign-in or being stored in a form that breaks the lowercase CHECK.
    try:
        return normalize_email(raw)
    except InvalidEmailError:
        return None
