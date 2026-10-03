from typing import TYPE_CHECKING

from sqlalchemy import false, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.user_identity import UserIdentity


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """The person/account. Credentials live on user_identities, never here (D1)."""

    __tablename__ = "users"

    # True for guest sign-ups that have not linked an identity yet.
    is_guest: Mapped[bool] = mapped_column(default=False, server_default=false())
    is_active: Mapped[bool] = mapped_column(default=True, server_default=true())

    # Never lazy-loaded (async): queries that need it load it explicitly with selectinload.
    identities: Mapped[list[UserIdentity]] = relationship(
        back_populates="user",
        lazy="raise",
        passive_deletes=True,
        order_by="UserIdentity.id",
    )

    def __repr__(self) -> str:
        return f"User(id={self.id!s}, is_guest={self.is_guest})"
