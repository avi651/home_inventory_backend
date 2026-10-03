from enum import StrEnum

from sqlalchemy import CheckConstraint, Enum, String, UniqueConstraint, true
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

EMAIL_MAX_LENGTH = 320


class AuthProvider(StrEnum):
    EMAIL = "email"
    GOOGLE = "google"
    APPLE = "apple"
    GUEST = "guest"


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email"),
        UniqueConstraint("auth_provider", "provider_subject", name="uq_users_provider_subject"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint("position('@' in email) > 1", name="email_format"),
        CheckConstraint(
            "(auth_provider = 'email' AND email IS NOT NULL AND password_hash IS NOT NULL"
            " AND provider_subject IS NULL)"
            " OR (auth_provider IN ('google', 'apple') AND provider_subject IS NOT NULL"
            " AND provider_subject <> ''"
            " AND password_hash IS NULL)"
            " OR (auth_provider = 'guest' AND email IS NULL AND password_hash IS NULL"
            " AND provider_subject IS NULL)",
            name="auth_provider_fields",
        ),
    )

    # Stored lowercase; uniqueness is therefore case-insensitive.
    email: Mapped[str | None] = mapped_column(String(EMAIL_MAX_LENGTH))
    # Argon2id hash (Phase 2). Never serialised: response schemas must not include it.
    password_hash: Mapped[str | None] = mapped_column(String(255))
    auth_provider: Mapped[AuthProvider] = mapped_column(
        Enum(AuthProvider, name="auth_provider", values_callable=lambda e: [m.value for m in e])
    )
    # Stable subject ("sub") from Google/Apple ID tokens.
    provider_subject: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True, server_default=true())

    def __repr__(self) -> str:
        return f"User(id={self.id!s}, auth_provider={self.auth_provider!s})"
