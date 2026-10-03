from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import AuthProvider, User


async def create_user(db: AsyncSession, *, is_active: bool = True) -> User:
    """Minimal persisted user. Single place to update when users are reshaped (D1)."""
    user = User(auth_provider=AuthProvider.GUEST, is_active=is_active)
    db.add(user)
    await db.flush()
    return user
