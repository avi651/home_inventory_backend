import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.auth_session import AuthSession, SessionRevokeReason
from app.models.user import User


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

    async def get_with_user(
        self, *, session_id: uuid.UUID, user_id: uuid.UUID
    ) -> tuple[AuthSession, User] | None:
        """Both ids must match one row: a token can never borrow another user's session.

        The user's identities are loaded too: the principal's user view is derived from them.
        """
        result = await self._db.execute(
            select(AuthSession, User)
            .join(User, User.id == AuthSession.user_id)
            .options(selectinload(User.identities))
            .where(AuthSession.id == session_id, AuthSession.user_id == user_id)
        )
        row = result.one_or_none()
        return None if row is None else (row[0], row[1])

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
