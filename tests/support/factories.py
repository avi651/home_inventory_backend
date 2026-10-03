from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


async def create_user(db: AsyncSession, *, is_active: bool = True, is_guest: bool = True) -> User:
    """Minimal persisted user: a guest (no identities) unless is_guest=False."""
    user = User(is_guest=is_guest, is_active=is_active)
    db.add(user)
    await db.flush()
    return user
