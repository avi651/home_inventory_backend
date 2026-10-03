import uuid

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.models.user import User
from app.models.user_identity import IdentityProvider, UserIdentity


class IdentityRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def add(self, identity: UserIdentity) -> UserIdentity:
        self._db.add(identity)
        await self._db.flush()
        return identity

    async def get_by_provider_subject(
        self, provider: IdentityProvider, subject: str
    ) -> UserIdentity | None:
        """Sign-in lookup: exact (provider, subject) match; owner and their identities loaded."""
        result = await self._db.execute(
            select(UserIdentity)
            .options(joinedload(UserIdentity.user).selectinload(User.identities))
            .where(UserIdentity.provider == provider, UserIdentity.subject == subject)
        )
        return result.scalar_one_or_none()

    async def get_for_user(
        self, *, user_id: uuid.UUID, identity_id: uuid.UUID
    ) -> UserIdentity | None:
        """Ownership is part of the WHERE: another user's identity id finds nothing."""
        result = await self._db.execute(
            select(UserIdentity).where(
                UserIdentity.id == identity_id, UserIdentity.user_id == user_id
            )
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: uuid.UUID) -> list[UserIdentity]:
        result = await self._db.execute(
            select(UserIdentity).where(UserIdentity.user_id == user_id).order_by(UserIdentity.id)
        )
        return list(result.scalars())

    async def email_in_use(self, email: str) -> bool:
        """Any identity (email login, or a provider-verified address) already holds this email."""
        result = await self._db.execute(select(exists().where(UserIdentity.email == email)))
        return bool(result.scalar_one())
