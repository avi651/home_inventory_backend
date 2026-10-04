import uuid

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.room_fields import MAX_ROOM_NAME_LENGTH
from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Room(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A room inside a home; hard-deleted.

    No user_id: ownership is User -> Home -> Room (rooms.home_id -> homes.user_id). Every query
    must be scoped through the parent home's owner: there is no lookup by room id alone.
    """

    __tablename__ = "rooms"
    __table_args__ = (
        # One name per home, case-insensitively. Leading home_id also serves "list a home's
        # rooms" and the FK's cascade lookup, so no separate home_id index is needed.
        UniqueConstraint("home_id", "name_key", name="uq_rooms_home_id_name_key"),
        CheckConstraint("char_length(name) >= 1 AND name = btrim(name)", name="name_trimmed"),
        CheckConstraint("name_key ~ '^[0-9a-f]{64}$'", name="name_key_format"),
    )

    # Deleting a home deletes its rooms (and so does deleting the user, through the home).
    home_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("homes.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(MAX_ROOM_NAME_LENGTH))
    # SHA-256 of the case/compatibility-folded name (app.core.room_fields). Never returned.
    name_key: Mapped[str] = mapped_column(String(64))

    def __repr__(self) -> str:
        return f"Room(id={self.id!s})"
