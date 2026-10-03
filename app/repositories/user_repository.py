from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


class UserRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def add(self, user: User) -> User:
        self._db.add(user)
        await self._db.flush()
        return user
