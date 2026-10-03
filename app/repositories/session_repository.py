import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth_session import AuthSession, SessionRevokeReason


class SessionRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def add(self, auth_session: AuthSession) -> AuthSession:
        self._db.add(auth_session)
        await self._db.flush()
        return auth_session

    async def get_for_update(self, session_id: uuid.UUID) -> AuthSession | None:
        result = await self._db.execute(
            select(AuthSession)
            .where(AuthSession.id == session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return result.scalar_one_or_none()

    async def revoke(
        self,
        *,
        user_id: uuid.UUID,
        reason: SessionRevokeReason,
        now: datetime,
        session_id: uuid.UUID | None = None,
    ) -> int:
        """Revoke active sessions owned by user_id (one, or all). Ownership is part of the WHERE."""
        statement = (
            update(AuthSession)
            .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason)
            .returning(AuthSession.id)
            .execution_options(synchronize_session=False)
        )
        if session_id is not None:
            statement = statement.where(AuthSession.id == session_id)
        return len((await self._db.execute(statement)).all())
