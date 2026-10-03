"""Sign in with Google (Step 8): OAuth state lifecycle and Google identity -> user resolution.

Flow: start() stores a short-lived attempt and returns Google's authorization URL plus an
`attempt_token` that stays with the client. complete() consumes the attempt (single use),
redeems the code server-side with the attempt's PKCE verifier, validates the ID token and
signs in the user owning (google, sub) -- or creates one. Identity data never comes from the
client, and a matching email never links accounts (D1).

Logs carry user ids and fixed reasons only: never state, codes, tokens, subjects or emails.
"""

import base64
import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clock import Clock, utc_now
from app.exceptions.errors import (
    AccountLinkRequiredError,
    OAuthSignInFailedError,
    ProviderUnavailableError,
)
from app.models.oauth_login_attempt import OAuthLoginAttempt
from app.models.user import User
from app.models.user_identity import IdentityProvider, UserIdentity
from app.repositories.oauth_attempt_repository import OAuthAttemptRepository
from app.repositories.user_repository import UserRepository
from app.services import google_oauth
from app.services.google_oauth import GoogleIdentity, GoogleOAuthClient
from app.services.identity_service import IdentityAlreadyLinkedError, IdentityService
from app.services.session_service import SessionService, TokenPair

logger = logging.getLogger(__name__)

OAUTH_ATTEMPT_LIFETIME = timedelta(minutes=10)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass(frozen=True)
class OAuthStart:
    authorization_url: str
    attempt_token: str = field(repr=False)
    expires_in: int


class GoogleSignInService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        google: GoogleOAuthClient,
        sessions: SessionService,
        clock: Clock = utc_now,
    ) -> None:
        self._db = db
        self._google = google
        self._sessions = sessions
        self._clock = clock
        self._attempts = OAuthAttemptRepository(db)
        self._users = UserRepository(db)
        self._identities = IdentityService(db)

    async def start(self) -> OAuthStart:
        # 256-bit secrets. state travels through the browser; attempt_token never does.
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        attempt_token = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)  # 86 chars, within RFC 7636's 43-128
        now = self._clock()
        try:
            await self._attempts.delete_expired(now)
            await self._attempts.add(
                OAuthLoginAttempt(
                    provider=IdentityProvider.GOOGLE,
                    state_hash=_sha256(state),
                    binding_hash=_sha256(attempt_token),
                    nonce_hash=_sha256(nonce),
                    code_verifier=code_verifier,
                    expires_at=now + OAUTH_ATTEMPT_LIFETIME,
                )
            )
            await self._db.commit()
        except BaseException:
            await self._db.rollback()
            raise
        return OAuthStart(
            authorization_url=self._google.authorization_url(
                state=state, nonce=nonce, code_challenge=_code_challenge(code_verifier)
            ),
            attempt_token=attempt_token,
            expires_in=int(OAUTH_ATTEMPT_LIFETIME.total_seconds()),
        )

    async def complete(
        self, *, code: str, state: str, attempt_token: str
    ) -> tuple[User, TokenPair]:
        attempt = await self._consume_attempt(state, attempt_token)
        claims = await self._verified_identity(code, attempt)

        identity = await self._identities.resolve(IdentityProvider.GOOGLE, claims.subject)
        if identity is None:
            try:
                return await self._create_user(claims)
            except IdentityAlreadyLinkedError:
                # A concurrent first sign-in with the same Google account won the race.
                identity = await self._identities.resolve(IdentityProvider.GOOGLE, claims.subject)
                if identity is None:
                    raise OAuthSignInFailedError from None
        return await self._sign_in_existing(identity)

    async def _consume_attempt(self, state: str, attempt_token: str) -> OAuthLoginAttempt:
        """Single use: whoever presents a state burns it, whatever happens afterwards."""
        attempt = await self._attempts.consume(
            provider=IdentityProvider.GOOGLE, state_hash=_sha256(state)
        )
        await self._db.commit()
        if (
            attempt is None
            # Binds the callback to the client that called start(): a stolen code+state from
            # the redirect is useless without the attempt_token, which never left that client.
            or not hmac.compare_digest(attempt.binding_hash, _sha256(attempt_token))
            or self._clock() >= attempt.expires_at
        ):
            logger.info("google sign-in rejected reason=invalid_state")
            raise OAuthSignInFailedError
        return attempt

    async def _verified_identity(self, code: str, attempt: OAuthLoginAttempt) -> GoogleIdentity:
        try:
            id_token = await self._google.exchange_code(
                code=code, code_verifier=attempt.code_verifier
            )
            return await self._google.verify_id_token(id_token, nonce_hash=attempt.nonce_hash)
        except google_oauth.ProviderRejectedError as exc:
            logger.info("google sign-in rejected reason=%s", exc.reason)
            raise OAuthSignInFailedError from None
        except google_oauth.ProviderUnavailableError as exc:
            logger.warning("google sign-in unavailable reason=%s", exc.reason)
            raise ProviderUnavailableError from None

    async def _create_user(self, claims: GoogleIdentity) -> tuple[User, TokenPair]:
        if claims.email is not None and await self._identities.email_in_use(claims.email):
            logger.info("google sign-in refused reason=email_belongs_to_another_account")
            raise AccountLinkRequiredError
        user = User()
        try:
            await self._users.add(user)
            identity = await self._identities.link(
                user.id,
                IdentityProvider.GOOGLE,
                claims.subject,
                email=claims.email,
                email_verified=claims.email_verified,
            )
            identity.last_used_at = self._clock()
            await self._db.refresh(user, attribute_names=["identities"])
            # Commits user, identity and session together; any failure leaves none behind.
            pair = await self._sessions.start(user.id)
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("user created via google sign-in user_id=%s", user.id)
        return user, pair

    async def _sign_in_existing(self, identity: UserIdentity) -> tuple[User, TokenPair]:
        user = identity.user
        if not user.is_active:
            logger.info("google sign-in rejected reason=inactive_user user_id=%s", user.id)
            raise OAuthSignInFailedError
        identity.last_used_at = self._clock()
        try:
            pair = await self._sessions.start(user.id)
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("google sign-in succeeded user_id=%s session_id=%s", user.id, pair.session_id)
        return user, pair
