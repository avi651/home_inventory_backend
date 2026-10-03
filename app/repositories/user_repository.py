from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import AuthProvider, User


class UserRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def add(self, user: User) -> User:
        self._db.add(user)
        await self._db.flush()
        return user

    async def get_password_user(self, normalized_email: str) -> User | None:
        """Only email/password accounts can password-login."""
        result = await self._db.execute(
            select(User).where(
                User.email == normalized_email, User.auth_provider == AuthProvider.EMAIL
            )
        )
        return result.scalar_one_or_none()
