from datetime import datetime

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_login_attempt import OAuthLoginAttempt
from app.models.user_identity import IdentityProvider


class OAuthAttemptRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def add(self, attempt: OAuthLoginAttempt) -> OAuthLoginAttempt:
        self._db.add(attempt)
        await self._db.flush()
        return attempt

    async def consume(
        self, *, provider: IdentityProvider, state_hash: str
    ) -> OAuthLoginAttempt | None:
        """Delete-and-return: of concurrent callbacks presenting one state, exactly one gets it."""
        result = await self._db.execute(
            delete(OAuthLoginAttempt)
            .where(
                OAuthLoginAttempt.provider == provider,
                OAuthLoginAttempt.state_hash == state_hash,
            )
            .returning(OAuthLoginAttempt)
        )
        return result.scalar_one_or_none()

    async def delete_expired(self, now: datetime) -> None:
        await self._db.execute(
            delete(OAuthLoginAttempt)
            .where(OAuthLoginAttempt.expires_at <= now)
            .execution_options(synchronize_session=False)
        )
