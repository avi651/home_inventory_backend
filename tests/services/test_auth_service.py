from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.password_policy import PasswordViolation
from app.core.passwords import Argon2Params, PasswordHasher
from app.core.rate_limit import AuthRateLimits, InMemoryRateLimiter, RateLimit
from app.core.tokens import AccessTokenService
from app.exceptions.errors import (
    InvalidCredentialsError,
    RateLimitedError,
    RegistrationUnavailableError,
    WeakPasswordError,
)
from app.models.user import AuthProvider, User
from app.services.auth_service import AuthService
from app.services.session_service import SessionService
from tests.conftest import GENEROUS_RATE_LIMITS
from tests.support.clock import FrozenClock
from tests.support.factories import create_user
from tests.support.passwords import STRONG_PASSWORD, fast_hasher

EMAIL = "alice@example.com"


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def hasher() -> PasswordHasher:
    return fast_hasher()


def build_service(
    db: AsyncSession,
    settings: Settings,
    clock: FrozenClock,
    hasher: PasswordHasher,
    limits: AuthRateLimits = GENEROUS_RATE_LIMITS,
) -> AuthService:
    sessions = SessionService(db, AccessTokenService(settings, clock=clock), settings, clock=clock)
    return AuthService(
        db,
        hasher=hasher,
        sessions=sessions,
        rate_limiter=InMemoryRateLimiter(clock=clock),
        rate_limits=limits,
    )


@pytest.fixture
def service(
    db_session: AsyncSession, test_settings: Settings, clock: FrozenClock, hasher: PasswordHasher
) -> AuthService:
    return build_service(db_session, test_settings, clock, hasher)


async def count_users(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(User))).scalar_one()


class TestRegister:
    async def test_creates_email_user_with_argon2id_hash(
        self, service: AuthService, hasher: PasswordHasher
    ) -> None:
        user, pair = await service.register("Alice@Example.com", STRONG_PASSWORD)

        assert user.auth_provider is AuthProvider.EMAIL
        assert user.email == EMAIL
        assert user.password_hash is not None
        assert user.password_hash.startswith("$argon2id$")
        assert STRONG_PASSWORD not in user.password_hash
        assert await hasher.verify(user.password_hash, STRONG_PASSWORD)
        assert pair.refresh_token
        assert pair.access_token

    async def test_weak_password_reports_codes_and_creates_nothing(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        before = await count_users(db_session)

        with pytest.raises(WeakPasswordError) as exc_info:
            await service.register(EMAIL, "alice-short")

        assert PasswordViolation.TOO_SHORT in exc_info.value.violations
        assert PasswordViolation.CONTAINS_EMAIL in exc_info.value.violations
        assert await count_users(db_session) == before

    async def test_duplicate_email_is_unavailable(self, service: AuthService) -> None:
        await service.register(EMAIL, STRONG_PASSWORD)

        with pytest.raises(RegistrationUnavailableError):
            await service.register("ALICE@example.com", "another strong passphrase")

    async def test_duplicate_still_pays_the_hashing_cost(
        self, service: AuthService, hasher: PasswordHasher, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Timing: 'email taken' must not be faster than a real registration."""
        await service.register(EMAIL, STRONG_PASSWORD)
        hashed: list[str] = []
        original = hasher.hash

        async def spy(password: str) -> str:
            hashed.append("x")
            return await original(password)

        monkeypatch.setattr(hasher, "hash", spy)

        with pytest.raises(RegistrationUnavailableError):
            await service.register(EMAIL, "another strong passphrase")

        assert hashed == ["x"]

    async def test_user_and_session_are_created_atomically(
        self,
        service: AuthService,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = await count_users(db_session)

        async def fail(*_: object) -> None:
            raise RuntimeError("session creation failed")

        monkeypatch.setattr(service._sessions, "start", fail)

        with pytest.raises(RuntimeError):
            await service.register(EMAIL, STRONG_PASSWORD)

        assert await count_users(db_session) == before


class TestLogin:
    async def test_success_starts_a_new_session(self, service: AuthService) -> None:
        _, first = await service.register(EMAIL, STRONG_PASSWORD)

        user, second = await service.login("ALICE@example.com", STRONG_PASSWORD)

        assert user.email == EMAIL
        assert second.session_id != first.session_id

    @pytest.mark.parametrize(
        ("email", "password"),
        [
            (EMAIL, "wrong passphrase entirely"),
            ("nobody@example.com", STRONG_PASSWORD),
            (EMAIL, ""),
        ],
    )
    async def test_failures_raise_one_generic_error(
        self, service: AuthService, email: str, password: str
    ) -> None:
        await service.register(EMAIL, STRONG_PASSWORD)

        with pytest.raises(InvalidCredentialsError) as exc_info:
            await service.login(email, password)

        assert str(exc_info.value) == "Invalid email or password"

    async def test_inactive_user_gets_the_same_error_even_with_right_password(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        user, _ = await service.register(EMAIL, STRONG_PASSWORD)
        user.is_active = False
        await db_session.flush()

        with pytest.raises(InvalidCredentialsError):
            await service.login(EMAIL, STRONG_PASSWORD)

    async def test_non_email_accounts_cannot_password_login(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        db_session.add(
            User(
                auth_provider=AuthProvider.GOOGLE, provider_subject="g-1", email="gina@example.com"
            )
        )
        await db_session.flush()

        with pytest.raises(InvalidCredentialsError):
            await service.login("gina@example.com", STRONG_PASSWORD)

    @pytest.mark.parametrize("scenario", ["unknown_email", "oauth_user"])
    async def test_accounts_without_password_still_cost_a_verification(
        self,
        service: AuthService,
        db_session: AsyncSession,
        hasher: PasswordHasher,
        monkeypatch: pytest.MonkeyPatch,
        scenario: str,
    ) -> None:
        """Timing: unknown accounts must not answer faster than wrong passwords."""
        if scenario == "oauth_user":
            db_session.add(
                User(
                    auth_provider=AuthProvider.APPLE, provider_subject="a-1", email="x@example.com"
                )
            )
            await db_session.flush()
        calls: list[str] = []
        original = hasher.verify_dummy

        async def spy(password: str) -> None:
            calls.append("dummy")
            await original(password)

        monkeypatch.setattr(hasher, "verify_dummy", spy)

        with pytest.raises(InvalidCredentialsError):
            await service.login("x@example.com", STRONG_PASSWORD)

        assert calls == ["dummy"]

    async def test_outdated_hash_is_upgraded_on_login(
        self,
        db_session: AsyncSession,
        test_settings: Settings,
        clock: FrozenClock,
    ) -> None:
        weak = PasswordHasher(Argon2Params(time_cost=1, memory_cost=8, parallelism=1))
        strong = PasswordHasher(Argon2Params(time_cost=2, memory_cost=16, parallelism=1))
        user, _ = await build_service(db_session, test_settings, clock, weak).register(
            EMAIL, STRONG_PASSWORD
        )
        old_hash = user.password_hash

        await build_service(db_session, test_settings, clock, strong).login(EMAIL, STRONG_PASSWORD)

        await db_session.refresh(user)
        assert user.password_hash != old_hash
        assert user.password_hash is not None
        assert "$m=16,t=2,p=1$" in user.password_hash

    async def test_per_account_limit_applies_across_any_source(
        self,
        db_session: AsyncSession,
        test_settings: Settings,
        clock: FrozenClock,
        hasher: PasswordHasher,
    ) -> None:
        limits = AuthRateLimits(
            register_per_ip=GENEROUS_RATE_LIMITS.register_per_ip,
            login_per_ip=GENEROUS_RATE_LIMITS.login_per_ip,
            login_per_account=RateLimit(limit=2, window=timedelta(minutes=15)),
            refresh_per_ip=GENEROUS_RATE_LIMITS.refresh_per_ip,
        )
        service = build_service(db_session, test_settings, clock, hasher, limits)
        await service.register(EMAIL, STRONG_PASSWORD)

        for _ in range(2):
            with pytest.raises(InvalidCredentialsError):
                await service.login(EMAIL, "wrong passphrase entirely")

        # Even the correct password is refused once the account is throttled ...
        with pytest.raises(RateLimitedError) as exc_info:
            await service.login("Alice@Example.com", STRONG_PASSWORD)
        assert exc_info.value.headers == {"Retry-After": str(15 * 60)}

        # ... and an unknown account is throttled identically (no existence oracle).
        for _ in range(2):
            with pytest.raises(InvalidCredentialsError):
                await service.login("ghost@example.com", STRONG_PASSWORD)
        with pytest.raises(RateLimitedError):
            await service.login("ghost@example.com", STRONG_PASSWORD)

        clock.advance(timedelta(minutes=15))
        _, pair = await service.login(EMAIL, STRONG_PASSWORD)
        assert pair.access_token


async def test_existing_factory_users_are_unaffected(db_session: AsyncSession) -> None:
    # Guards the shared factory used by Step 3 tests.
    user = await create_user(db_session)

    assert user.auth_provider is AuthProvider.GUEST
