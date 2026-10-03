import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class SessionRevokeReason(StrEnum):
    LOGOUT = "logout"
    LOGOUT_ALL = "logout_all"
    REUSE_DETECTED = "reuse_detected"
    USER_REVOKED = "user_revoked"


class AuthSession(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One login on one device. Carried as `sid` in access tokens; revocation is immediate."""

    __tablename__ = "auth_sessions"
    __table_args__ = (
        CheckConstraint(
            "(revoked_at IS NULL) = (revoked_reason IS NULL)", name="revocation_consistent"
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # Absolute cap: a session cannot be extended past this by refreshing.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_refreshed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[SessionRevokeReason | None] = mapped_column(
        Enum(
            SessionRevokeReason,
            name="session_revoke_reason",
            values_callable=lambda e: [m.value for m in e],
        )
    )

    def __repr__(self) -> str:
        return f"AuthSession(id={self.id!s}, revoked={self.revoked_at is not None})"
