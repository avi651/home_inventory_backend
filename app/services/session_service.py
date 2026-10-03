import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clock import Clock, utc_now
from app.core.config import Settings
from app.core.refresh_tokens import (
    generate_refresh_token,
    hash_refresh_token,
    hashes_match,
    is_well_formed,
)
from app.core.tokens import AccessTokenService
from app.exceptions.errors import InvalidRefreshTokenError
from app.models.auth_session import AuthSession, SessionRevokeReason
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.session_repository import SessionRepository

logger = logging.getLogger(__name__)

# Absolute session lifetime: refreshing slides the idle expiry, never past this cap.
SESSION_MAX_LIFETIME = timedelta(days=90)


@dataclass(frozen=True)
class Principal:
    """The authenticated caller: an active user acting through one live session."""

    user: User
    session_id: uuid.UUID


@dataclass(frozen=True)
class TokenPair:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_in: int
    session_id: uuid.UUID
    token_type: str = "bearer"  # noqa: S105 - OAuth token type label


class SessionService:
    """Login sessions: creation, refresh-token rotation with reuse detection, revocation.

    `revoke` is the single revocation path (logout, logout-all, reuse detection, and later
    device-token deactivation all go through it).
    """

    def __init__(
        self,
        db: AsyncSession,
        access_tokens: AccessTokenService,
        settings: Settings,
        clock: Clock = utc_now,
    ) -> None:
        self._db = db
        self._access_tokens = access_tokens
        self._clock = clock
        self._idle_lifetime = timedelta(days=settings.refresh_token_expire_days)
        self._sessions = SessionRepository(db)
        self._refresh_tokens = RefreshTokenRepository(db)

    async def start(self, user_id: uuid.UUID) -> TokenPair:
        now = self._clock()
        auth_session = await self._sessions.add(
            AuthSession(user_id=user_id, expires_at=now + SESSION_MAX_LIFETIME)
        )
        return await self._issue_and_commit(auth_session, now)

    async def refresh(self, refresh_token: str) -> TokenPair:
        """Rotate: the presented token is consumed and a new pair issued, atomically."""
        if not is_well_formed(refresh_token):
            raise InvalidRefreshTokenError
        token_hash = hash_refresh_token(refresh_token)
        try:
            # Lock order: token row, then session row. Concurrent rotations of the same token
            # serialise here; the loser re-reads the committed row and sees it already used.
            stored = await self._refresh_tokens.get_by_hash_for_update(token_hash)
            if stored is None or not hashes_match(stored.token_hash, token_hash):
                raise InvalidRefreshTokenError
            auth_session = await self._sessions.get_for_update(stored.session_id)
            if auth_session is None:
                raise InvalidRefreshTokenError

            now = self._clock()
            if stored.used_at is not None:
                await self._handle_reuse(auth_session)
                raise InvalidRefreshTokenError
            if not await self._is_refreshable(auth_session, stored, now):
                raise InvalidRefreshTokenError

            stored.used_at = now
            auth_session.last_refreshed_at = now
            return await self._issue_and_commit(auth_session, now)
        except BaseException:
            # Covers rejections and unexpected failures: nothing half-applied survives, so the
            # presented token stays usable unless the rotation fully committed.
            await self._db.rollback()
            raise

    async def get_active_principal(
        self, *, user_id: uuid.UUID, session_id: uuid.UUID
    ) -> Principal | None:
        """Per-request check behind every access token: makes logout/revocation immediate."""
        found = await self._sessions.get_with_user(session_id=session_id, user_id=user_id)
        if found is None:
            return None
        auth_session, user = found
        if (
            auth_session.revoked_at is not None
            or self._clock() >= auth_session.expires_at
            or not user.is_active
        ):
            return None
        return Principal(user=user, session_id=auth_session.id)

    async def revoke(
        self,
        *,
        user_id: uuid.UUID,
        reason: SessionRevokeReason,
        session_id: uuid.UUID | None = None,
    ) -> int:
        """Revoke one session (or all, if session_id is None) owned by user_id. Idempotent."""
        revoked = await self._sessions.revoke(
            user_id=user_id, reason=reason, now=self._clock(), session_id=session_id
        )
        await self._db.commit()
        if revoked:
            logger.info(
                "auth sessions revoked user_id=%s session_id=%s reason=%s count=%d",
                user_id,
                session_id or "all",
                reason.value,
                revoked,
            )
        return revoked

    async def _handle_reuse(self, auth_session: AuthSession) -> None:
        # A consumed token came back: either the client replayed it or it was stolen. We cannot
        # tell which, so the whole session dies (strict policy, ARCHITECTURE.md D3).
        logger.warning(
            "refresh token reuse detected; revoking session user_id=%s session_id=%s",
            auth_session.user_id,
            auth_session.id,
        )
        # Commits the revocation, so it persists even though the caller raises afterwards.
        await self.revoke(
            user_id=auth_session.user_id,
            session_id=auth_session.id,
            reason=SessionRevokeReason.REUSE_DETECTED,
        )

    async def _is_refreshable(
        self, auth_session: AuthSession, stored: RefreshToken, now: datetime
    ) -> bool:
        if auth_session.revoked_at is not None:
            return False
        if now >= auth_session.expires_at or now >= stored.expires_at:
            return False
        user = await self._db.get(User, auth_session.user_id)
        return user is not None and user.is_active

    async def _issue_and_commit(self, auth_session: AuthSession, now: datetime) -> TokenPair:
        raw_token = generate_refresh_token()
        await self._refresh_tokens.add(
            RefreshToken(
                session_id=auth_session.id,
                token_hash=hash_refresh_token(raw_token),
                expires_at=min(now + self._idle_lifetime, auth_session.expires_at),
            )
        )
        # Issued before commit: if issuing fails, the transaction rolls back untouched.
        access = self._access_tokens.issue(user_id=auth_session.user_id, session_id=auth_session.id)
        await self._db.commit()
        return TokenPair(
            access_token=access.token,
            refresh_token=raw_token,
            expires_in=access.expires_in,
            session_id=auth_session.id,
        )
