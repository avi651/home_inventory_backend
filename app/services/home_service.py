"""Homes: business rules on top of the owner-scoped repository.

The owner is always the authenticated principal's user id, passed in by the route; nothing a
client sends can choose it. Logs carry user and home ids only: home names are user content
(often addresses) and never logged.
"""

import logging
import uuid
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.home_fields import home_name_key, normalize_currency, normalize_home_name
from app.exceptions.errors import HomeLimitReachedError, HomeNameTakenError, HomeNotFoundError
from app.models.home import Home
from app.repositories.home_repository import HomeRepository
from app.services.identity_service import violated_constraint

logger = logging.getLogger(__name__)

MAX_HOMES_PER_USER = 50
_NAME_UNIQUE_CONSTRAINT = "uq_homes_user_id_name_key"


class HomeService:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._homes = HomeRepository(db)

    async def create(self, user_id: uuid.UUID, *, name: str, currency: str) -> Home:
        name = normalize_home_name(name)
        home = Home(
            user_id=user_id,
            name=name,
            name_key=home_name_key(name),
            currency=normalize_currency(currency),
        )
        try:
            # The user-row lock serialises concurrent creates, so the cap holds under races.
            if await self._homes.count_for_user_locked(user_id) >= MAX_HOMES_PER_USER:
                raise HomeLimitReachedError
            await self._homes.add(home)
            await self._db.commit()
        except IntegrityError as exc:
            await self._db.rollback()
            # The unique constraint (not a prior SELECT) decides: race-free.
            if violated_constraint(exc) == _NAME_UNIQUE_CONSTRAINT:
                raise HomeNameTakenError from None
            raise
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("home created user_id=%s home_id=%s", user_id, home.id)
        return home

    async def list(self, user_id: uuid.UUID) -> list[Home]:
        return await self._homes.list_for_user(user_id)

    async def get(self, user_id: uuid.UUID, home_id: uuid.UUID) -> Home:
        home = await self._homes.get_for_user(user_id=user_id, home_id=home_id)
        if home is None:
            raise HomeNotFoundError
        return home

    async def update(
        self,
        user_id: uuid.UUID,
        home_id: uuid.UUID,
        *,
        name: str | None = None,
        currency: str | None = None,
    ) -> Home:
        """Change only the given fields; the others keep their stored values."""
        values: dict[str, Any] = {}
        if name is not None:
            values["name"] = normalize_home_name(name)
            values["name_key"] = home_name_key(values["name"])
        if currency is not None:
            values["currency"] = normalize_currency(currency)
        if not values:
            raise ValueError("nothing to update")
        try:
            home = await self._homes.update_for_user(
                user_id=user_id, home_id=home_id, values=values
            )
            if home is None:
                raise HomeNotFoundError
            await self._db.commit()
        except IntegrityError as exc:
            await self._db.rollback()
            if violated_constraint(exc) == _NAME_UNIQUE_CONSTRAINT:
                raise HomeNameTakenError from None
            raise
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("home updated user_id=%s home_id=%s", user_id, home.id)
        return home

    async def delete(self, user_id: uuid.UUID, home_id: uuid.UUID) -> None:
        try:
            if not await self._homes.delete_for_user(user_id=user_id, home_id=home_id):
                raise HomeNotFoundError
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("home deleted user_id=%s home_id=%s", user_id, home_id)
