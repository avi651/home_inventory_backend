from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.user_identity import IdentityProvider


class OAuthLoginAttempt(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One pending provider sign-in (OAuth state). Short-lived and deleted when presented.

    Only SHA-256 digests of the state, client binding token and nonce are stored; the PKCE
    verifier must be kept as-is because it is sent to the provider during the code exchange.
    Lives in PostgreSQL (not process memory) so single use holds across workers.
    """

    __tablename__ = "oauth_login_attempts"
    __table_args__ = (
        CheckConstraint("state_hash ~ '^[0-9a-f]{64}$'", name="state_hash_format"),
        CheckConstraint("binding_hash ~ '^[0-9a-f]{64}$'", name="binding_hash_format"),
        CheckConstraint("nonce_hash ~ '^[0-9a-f]{64}$'", name="nonce_hash_format"),
        # RFC 7636 4.1: 43-128 unreserved characters.
        CheckConstraint("code_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'", name="code_verifier_format"),
    )

    provider: Mapped[IdentityProvider] = mapped_column(
        Enum(
            IdentityProvider,
            name="identity_provider",
            values_callable=lambda e: [m.value for m in e],
            create_type=False,
        )
    )
    state_hash: Mapped[str] = mapped_column(String(64), unique=True)
    binding_hash: Mapped[str] = mapped_column(String(64))
    nonce_hash: Mapped[str] = mapped_column(String(64))
    code_verifier: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    def __repr__(self) -> str:
        return f"OAuthLoginAttempt(id={self.id!s}, provider={self.provider!s})"
