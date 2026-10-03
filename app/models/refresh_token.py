import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RefreshToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single-use link in a session's rotation chain. Stores only the SHA-256 of the token."""

    __tablename__ = "refresh_tokens"
    __table_args__ = (
        # The database itself refuses anything but a SHA-256 hex digest: plaintext cannot land here.
        CheckConstraint("token_hash ~ '^[0-9a-f]{64}$'", name="token_hash_format"),
        # At most one usable token per session: a backstop if rotation ever raced.
        Index(
            "uq_refresh_tokens_one_active_per_session",
            "session_id",
            unique=True,
            postgresql_where=text("used_at IS NULL"),
        ),
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("auth_sessions.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # Idle expiry; never later than the session's absolute expiry.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Set on rotation. Presenting a token with used_at set is reuse.
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"RefreshToken(id={self.id!s}, used={self.used_at is not None})"
