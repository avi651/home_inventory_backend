import uuid
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.home import Home
from app.models.user import User


class HomeRepository:
    """Owner-scoped data access. The owner is part of every WHERE clause: there is deliberately
    no way to load, change or delete a home by id alone (ARCHITECTURE.md §5, IDOR/BOLA)."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def add(self, home: Home) -> Home:
        self._db.add(home)
        await self._db.flush()
        return home

    async def get_for_user(self, *, user_id: uuid.UUID, home_id: uuid.UUID) -> Home | None:
        result = await self._db.execute(
            select(Home).where(Home.id == home_id, Home.user_id == user_id)
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: uuid.UUID) -> list[Home]:
        # UUIDv7 ids are time-ordered: oldest first.
        result = await self._db.execute(
            select(Home).where(Home.user_id == user_id).order_by(Home.id)
        )
        return list(result.scalars())

    async def count_for_user_locked(self, user_id: uuid.UUID) -> int:
        """Count the user's homes while holding a lock on their user row.

        Concurrent creates for the same user queue on this lock, so the per-user cap cannot be
        exceeded by racing requests. Released when the caller's transaction ends.
        """
        await self._db.execute(select(User.id).where(User.id == user_id).with_for_update())
        result = await self._db.execute(
            select(func.count()).select_from(Home).where(Home.user_id == user_id)
        )
        return result.scalar_one()

    async def update_for_user(
        self, *, user_id: uuid.UUID, home_id: uuid.UUID, values: dict[str, Any]
    ) -> Home | None:
        """Single atomic UPDATE scoped by owner; None if no such home for this user."""
        result = await self._db.execute(
            update(Home)
            .where(Home.id == home_id, Home.user_id == user_id)
            .values(**values)
            .returning(Home)
            .execution_options(populate_existing=True, synchronize_session=False)
        )
        return result.scalar_one_or_none()

    async def delete_for_user(self, *, user_id: uuid.UUID, home_id: uuid.UUID) -> bool:
        result = await self._db.execute(
            delete(Home)
            .where(Home.id == home_id, Home.user_id == user_id)
            .returning(Home.id)
            .execution_options(synchronize_session=False)
        )
        return result.scalar_one_or_none() is not None
