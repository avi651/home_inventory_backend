import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clock import Clock, utc_now
from app.core.emails import normalize_email
from app.core.password_policy import check_password
from app.core.passwords import PasswordHasher
from app.core.rate_limit import AuthRateLimits, RateLimiter, account_key
from app.exceptions.errors import (
    InvalidCredentialsError,
    RateLimitedError,
    RegistrationUnavailableError,
    WeakPasswordError,
)
from app.models.user import User
from app.models.user_identity import IdentityProvider
from app.repositories.user_repository import UserRepository
from app.services.identity_service import IdentityAlreadyLinkedError, IdentityService
from app.services.session_service import SessionService, TokenPair

logger = logging.getLogger(__name__)


class AuthService:
    """Email/password registration and login, and guest sign-in. Sessions/tokens are delegated
    to SessionService; credentials are found and attached through IdentityService (D1).

    Logs carry user ids only: never emails, passwords, hashes or tokens.
    """

    def __init__(
        self,
        db: AsyncSession,
        *,
        hasher: PasswordHasher,
        sessions: SessionService,
        rate_limiter: RateLimiter,
        rate_limits: AuthRateLimits,
        clock: Clock = utc_now,
    ) -> None:
        self._db = db
        self._hasher = hasher
        self._sessions = sessions
        self._rate_limiter = rate_limiter
        self._rate_limits = rate_limits
        self._clock = clock
        self._users = UserRepository(db)
        self._identities = IdentityService(db)

    async def register(self, email: str, password: str) -> tuple[User, TokenPair]:
        email = normalize_email(email)
        if violations := check_password(password, email=email):
            raise WeakPasswordError(violations)
        # Hash before checking for duplicates: a taken email costs the same time as a new one.
        password_hash = await self._hasher.hash(password)
        user = User()
        try:
            await self._users.add(user)
            # The identity's unique constraint (not a prior SELECT) decides: race-free and
            # enumeration-safe.
            await self._identities.link(
                user.id, IdentityProvider.EMAIL, email, password_hash=password_hash
            )
            await self._db.refresh(user, attribute_names=["identities"])
            # Commits user, identity and session together; any failure leaves none behind.
            pair = await self._sessions.start(user.id)
        except IdentityAlreadyLinkedError:
            await self._db.rollback()
            raise RegistrationUnavailableError from None
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("user registered user_id=%s", user.id)
        return user, pair

    async def sign_in_as_guest(self) -> tuple[User, TokenPair]:
        """A brand-new guest: no identities and no credentials, just a session (ARCHITECTURE.md
        §3). Upgrading later links an identity to this same user id, so its data stays attached.
        """
        # identities=[] marks the (empty) collection as loaded: the user view needs no query.
        user = User(is_guest=True, identities=[])
        try:
            await self._users.add(user)
            # Commits user and session together; any failure leaves neither behind.
            pair = await self._sessions.start(user.id)
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("guest user created user_id=%s session_id=%s", user.id, pair.session_id)
        return user, pair

    async def login(self, email: str, password: str) -> tuple[User, TokenPair]:
        try:
            email = normalize_email(email)
        except ValueError:
            await self._hasher.verify_dummy(password)
            raise InvalidCredentialsError from None
        # Counted before the lookup, so throttling looks the same for existing and unknown accounts.
        limit = await self._rate_limiter.hit(
            f"login_per_account:{account_key(email)}", self._rate_limits.login_per_account
        )
        if not limit.allowed:
            logger.warning("login throttled for an account (per-account limit)")
            raise RateLimitedError(limit.retry_after)

        identity = await self._identities.resolve(IdentityProvider.EMAIL, email)
        if identity is None or identity.password_hash is None:
            await self._hasher.verify_dummy(password)  # same cost as a real verification
            logger.info("login failed")
            raise InvalidCredentialsError
        user = identity.user
        # Verify before checking is_active: an inactive account must not answer faster.
        if not await self._hasher.verify(identity.password_hash, password) or not user.is_active:
            logger.info("login failed user_id=%s", user.id)
            raise InvalidCredentialsError

        if self._hasher.needs_rehash(identity.password_hash):
            identity.password_hash = await self._hasher.hash(password)
        identity.last_used_at = self._clock()  # committed with the session
        try:
            pair = await self._sessions.start(user.id)
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("login succeeded user_id=%s session_id=%s", user.id, pair.session_id)
        return user, pair
