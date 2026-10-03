import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    String,
    UniqueConstraint,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.user import User

EMAIL_MAX_LENGTH = 320
# Email subjects are the normalized address; Google/Apple `sub` values are at most 255 chars.
SUBJECT_MAX_LENGTH = EMAIL_MAX_LENGTH


class IdentityProvider(StrEnum):
    """How a user signs in. Guests are users.is_guest with no identity (ARCHITECTURE.md §3)."""

    EMAIL = "email"
    GOOGLE = "google"
    APPLE = "apple"


class UserIdentity(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One sign-in method of one user (D1). A user may link one identity per provider."""

    __tablename__ = "user_identities"
    __table_args__ = (
        # One account per email login / per Google or Apple subject.
        UniqueConstraint("provider", "subject", name="uq_user_identities_provider_subject"),
        UniqueConstraint("user_id", "provider", name="uq_user_identities_user_id_provider"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint("position('@' in email) > 1", name="email_format"),
        CheckConstraint(
            "(provider = 'email' AND email IS NOT NULL AND subject = email"
            " AND password_hash IS NOT NULL)"
            " OR (provider IN ('google', 'apple') AND subject <> '' AND password_hash IS NULL)",
            name="provider_fields",
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    provider: Mapped[IdentityProvider] = mapped_column(
        Enum(
            IdentityProvider,
            name="identity_provider",
            values_callable=lambda e: [m.value for m in e],
        )
    )
    # email: the normalized address; google/apple: the ID token `sub` (case-sensitive, opaque).
    subject: Mapped[str] = mapped_column(String(SUBJECT_MAX_LENGTH))
    # Required for email; for Google/Apple only a provider-verified address. Never used to link:
    # indexed so a new provider sign-in can detect "this email already has an account" (409).
    email: Mapped[str | None] = mapped_column(String(EMAIL_MAX_LENGTH), index=True)
    email_verified: Mapped[bool] = mapped_column(default=False, server_default=false())
    # Argon2id, email identities only. Never serialised: response schemas must not include it.
    password_hash: Mapped[str | None] = mapped_column(String(255))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="identities", lazy="raise")

    def __repr__(self) -> str:
        return f"UserIdentity(id={self.id!s}, provider={self.provider!s})"
