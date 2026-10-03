"""UserRead keeps the Step 4 API shape while its email/auth_provider come from identities (D1)."""

import uuid
from datetime import UTC, datetime

from app.models.user import User
from app.models.user_identity import IdentityProvider, UserIdentity
from app.schemas.user import UserRead

FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def make_user(*identities: UserIdentity, is_guest: bool = False) -> User:
    return User(
        id=uuid.uuid7(),
        is_guest=is_guest,
        is_active=True,
        created_at=NOW,
        identities=list(identities),
    )


def identity(provider: IdentityProvider, subject: str, email: str | None = None) -> UserIdentity:
    return UserIdentity(
        id=uuid.uuid7(),
        provider=provider,
        subject=subject,
        email=email,
        password_hash=FAKE_HASH if provider is IdentityProvider.EMAIL else None,
    )


def test_guest_has_no_email_and_guest_provider() -> None:
    view = UserRead.from_user(make_user(is_guest=True))

    assert (view.email, view.auth_provider) == (None, "guest")


def test_email_identity_is_preferred_over_oauth() -> None:
    user = make_user(
        identity(IdentityProvider.GOOGLE, "g-1", "gina@example.com"),
        identity(IdentityProvider.EMAIL, "alice@example.com", "alice@example.com"),
    )

    view = UserRead.from_user(user)

    assert (view.email, view.auth_provider) == ("alice@example.com", "email")


def test_oauth_only_user_shows_its_first_linked_identity() -> None:
    user = make_user(
        identity(IdentityProvider.APPLE, "a-1"),
        identity(IdentityProvider.GOOGLE, "g-1", "gina@example.com"),
    )

    view = UserRead.from_user(user)

    assert (view.email, view.auth_provider) == (None, "apple")


def test_view_never_carries_credentials_or_subjects() -> None:
    user = make_user(identity(IdentityProvider.EMAIL, "alice@example.com", "alice@example.com"))
    user.identities.append(identity(IdentityProvider.GOOGLE, "g-secret-sub"))

    dumped = UserRead.from_user(user).model_dump_json()

    assert set(UserRead.model_fields) == {"id", "email", "auth_provider", "is_active", "created_at"}
    assert FAKE_HASH not in dumped
    assert "g-secret-sub" not in dumped
