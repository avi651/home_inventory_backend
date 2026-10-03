import logging

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

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
from app.models.user import AuthProvider, User
from app.repositories.user_repository import UserRepository
from app.services.session_service import SessionService, TokenPair

logger = logging.getLogger(__name__)

_EMAIL_UNIQUE_CONSTRAINT = "uq_users_email"


def _violated_constraint(exc: IntegrityError) -> str | None:
    diag = getattr(exc.orig, "diag", None)
    return getattr(diag, "constraint_name", None)


class AuthService:
    """Email/password registration and login. Sessions/tokens are delegated to SessionService.

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
    ) -> None:
        self._db = db
        self._hasher = hasher
        self._sessions = sessions
        self._rate_limiter = rate_limiter
        self._rate_limits = rate_limits
        self._users = UserRepository(db)

    async def register(self, email: str, password: str) -> tuple[User, TokenPair]:
        email = normalize_email(email)
        if violations := check_password(password, email=email):
            raise WeakPasswordError(violations)
        # Hash before checking for duplicates: a taken email costs the same time as a new one.
        password_hash = await self._hasher.hash(password)
        user = User(auth_provider=AuthProvider.EMAIL, email=email, password_hash=password_hash)
        try:
            await self._users.add(user)
            # Commits user and session together; any failure leaves neither behind.
            pair = await self._sessions.start(user.id)
        except IntegrityError as exc:
            await self._db.rollback()
            # The unique constraint (not a prior SELECT) decides: race-free and enumeration-safe.
            if _violated_constraint(exc) == _EMAIL_UNIQUE_CONSTRAINT:
                raise RegistrationUnavailableError from None
            raise
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("user registered user_id=%s", user.id)
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

        user = await self._users.get_password_user(email)
        if user is None or user.password_hash is None:
            await self._hasher.verify_dummy(password)  # same cost as a real verification
            logger.info("login failed")
            raise InvalidCredentialsError
        # Verify before checking is_active: an inactive account must not answer faster.
        if not await self._hasher.verify(user.password_hash, password) or not user.is_active:
            logger.info("login failed user_id=%s", user.id)
            raise InvalidCredentialsError

        if self._hasher.needs_rehash(user.password_hash):
            user.password_hash = await self._hasher.hash(password)  # committed with the session
        try:
            pair = await self._sessions.start(user.id)
        except BaseException:
            await self._db.rollback()
            raise
        logger.info("login succeeded user_id=%s session_id=%s", user.id, pair.session_id)
        return user, pair
