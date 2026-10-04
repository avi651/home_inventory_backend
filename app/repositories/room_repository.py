import uuid

from sqlalchemy import ColumnElement, delete, func, insert, literal, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.home import Home
from app.models.room import Room


def _owned_home(*, user_id: uuid.UUID, home_id: uuid.UUID) -> ColumnElement[bool]:
    return (Home.id == home_id) & (Home.user_id == user_id)


def _in_owned_home(*, user_id: uuid.UUID, home_id: uuid.UUID) -> ColumnElement[bool]:
    """The room's home is the requested one *and* belongs to the user.

    The subquery alone implies the equality; it is kept explicit so the planner can use the
    (home_id, name_key) index directly.
    """
    return (Room.home_id == home_id) & Room.home_id.in_(
        select(Home.id).where(_owned_home(user_id=user_id, home_id=home_id))
    )


class RoomRepository:
    """Data access scoped by the full chain User -> Home -> Room (ARCHITECTURE.md §5, IDOR/BOLA).

    Every method takes the owner and the parent home, and room-level methods the room too; each
    id is part of one WHERE clause. There is deliberately no lookup by room id alone. Anything
    outside the caller's own home is "not found" (None/False/[]) and changes nothing.
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def add(
        self, *, user_id: uuid.UUID, home_id: uuid.UUID, name: str, name_key: str
    ) -> Room | None:
        """Single INSERT ... SELECT from the owned home; None if the user does not own it."""
        owned = select(literal(uuid.uuid7()), Home.id, literal(name), literal(name_key)).where(
            _owned_home(user_id=user_id, home_id=home_id)
        )
        result = await self._db.execute(
            select(Room).from_statement(
                insert(Room)
                .from_select(["id", "home_id", "name", "name_key"], owned)
                .returning(*Room.__table__.c)
            )
        )
        return result.scalar_one_or_none()

    async def get_for_user(
        self, *, user_id: uuid.UUID, home_id: uuid.UUID, room_id: uuid.UUID
    ) -> Room | None:
        result = await self._db.execute(
            select(Room).where(Room.id == room_id, _in_owned_home(user_id=user_id, home_id=home_id))
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, *, user_id: uuid.UUID, home_id: uuid.UUID) -> list[Room]:
        # Oldest first; id breaks created_at ties so the order is deterministic.
        result = await self._db.execute(
            select(Room)
            .where(_in_owned_home(user_id=user_id, home_id=home_id))
            .order_by(Room.created_at, Room.id)
        )
        return list(result.scalars())

    async def count_for_user_locked(self, *, user_id: uuid.UUID, home_id: uuid.UUID) -> int | None:
        """Count the home's rooms while holding a lock on the owned home row.

        Concurrent room creates in the same home queue on this lock, so the per-home cap cannot
        be exceeded by racing requests. Released when the caller's transaction ends. None if the
        user does not own the home: no lock is taken on anyone else's row.
        """
        locked = await self._db.execute(
            select(Home.id).where(_owned_home(user_id=user_id, home_id=home_id)).with_for_update()
        )
        if locked.scalar_one_or_none() is None:
            return None
        result = await self._db.execute(
            select(func.count()).select_from(Room).where(Room.home_id == home_id)
        )
        return result.scalar_one()

    async def update_for_user(
        self,
        *,
        user_id: uuid.UUID,
        home_id: uuid.UUID,
        room_id: uuid.UUID,
        name: str,
        name_key: str,
    ) -> Room | None:
        """Single atomic UPDATE scoped by owner and home; None if no such room there.

        Only the name can change: a room is never moved to another home.
        """
        result = await self._db.execute(
            update(Room)
            .where(Room.id == room_id, _in_owned_home(user_id=user_id, home_id=home_id))
            .values(name=name, name_key=name_key)
            .returning(Room)
            .execution_options(populate_existing=True, synchronize_session=False)
        )
        return result.scalar_one_or_none()

    async def delete_for_user(
        self, *, user_id: uuid.UUID, home_id: uuid.UUID, room_id: uuid.UUID
    ) -> bool:
        result = await self._db.execute(
            delete(Room)
            .where(Room.id == room_id, _in_owned_home(user_id=user_id, home_id=home_id))
            .returning(Room.id)
            .execution_options(synchronize_session=False)
        )
        return result.scalar_one_or_none() is not None
