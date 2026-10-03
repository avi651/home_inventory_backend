import uuid

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.home_fields import MAX_HOME_NAME_LENGTH
from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Home(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A property the user inventories. Owned by exactly one user; hard-deleted.

    Every query must be scoped by user_id (see HomeRepository): there is no unscoped access.
    """

    __tablename__ = "homes"
    __table_args__ = (
        # One name per user, case-insensitively. Leading user_id also serves "list my homes"
        # and the FK's cascade lookup, so no separate user_id index is needed.
        UniqueConstraint("user_id", "name_key", name="uq_homes_user_id_name_key"),
        CheckConstraint("char_length(name) >= 1 AND name = btrim(name)", name="name_trimmed"),
        CheckConstraint("name_key ~ '^[0-9a-f]{64}$'", name="name_key_format"),
        CheckConstraint("currency ~ '^[A-Z]{3}$'", name="currency_format"),
    )

    # Deleting a user deletes their homes (and, later, everything inside them).
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(MAX_HOME_NAME_LENGTH))
    # SHA-256 of the case/compatibility-folded name (app.core.home_fields). Never returned.
    name_key: Mapped[str] = mapped_column(String(64))
    # ISO 4217 alphabetic code; the allowlist is enforced by the service, the shape here.
    currency: Mapped[str] = mapped_column(String(3))

    def __repr__(self) -> str:
        return f"Home(id={self.id!s})"
