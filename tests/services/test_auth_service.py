import uuid
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
from app.models.auth_session import AuthSession
from app.models.user import User
from app.models.user_identity import IdentityProvider, UserIdentity
from app.services.auth_service import AuthService
from app.services.identity_service import IdentityService
from app.services.session_service import SessionService, TokenPair
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
        clock=clock,
    )


@pytest.fixture
def service(
    db_session: AsyncSession, test_settings: Settings, clock: FrozenClock, hasher: PasswordHasher
) -> AuthService:
    return build_service(db_session, test_settings, clock, hasher)


async def count_users(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(User))).scalar_one()


async def count_identities(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(UserIdentity))).scalar_one()


def email_identity(user: User) -> UserIdentity:
    (identity,) = [i for i in user.identities if i.provider is IdentityProvider.EMAIL]
    return identity


async def add_oauth_user(
    db: AsyncSession, provider: IdentityProvider, subject: str, email: str
) -> User:
    user = User()
    db.add(user)
    await db.flush()
    db.add(UserIdentity(user_id=user.id, provider=provider, subject=subject, email=email))
    await db.flush()
    return user


class TestRegister:
    async def test_creates_user_with_one_email_identity_holding_the_argon2id_hash(
        self, service: AuthService, hasher: PasswordHasher
    ) -> None:
        user, pair = await service.register("Alice@Example.com", STRONG_PASSWORD)

        assert user.is_guest is False
        assert len(user.identities) == 1
        identity = email_identity(user)
        assert identity.subject == identity.email == EMAIL
        assert identity.password_hash is not None
        assert identity.password_hash.startswith("$argon2id$")
        assert STRONG_PASSWORD not in identity.password_hash
        assert await hasher.verify(identity.password_hash, STRONG_PASSWORD)
        assert pair.refresh_token
        assert pair.access_token

    async def test_registration_is_resolvable_through_user_identities(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        user, _ = await service.register(EMAIL, STRONG_PASSWORD)

        owner = (
            await db_session.execute(
                select(UserIdentity.user_id).where(
                    UserIdentity.provider == IdentityProvider.EMAIL, UserIdentity.subject == EMAIL
                )
            )
        ).scalar_one()
        assert owner == user.id

    async def test_weak_password_reports_codes_and_creates_nothing(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        before = (await count_users(db_session), await count_identities(db_session))

        with pytest.raises(WeakPasswordError) as exc_info:
            await service.register(EMAIL, "alice-short")

        assert PasswordViolation.TOO_SHORT in exc_info.value.violations
        assert PasswordViolation.CONTAINS_EMAIL in exc_info.value.violations
        assert (await count_users(db_session), await count_identities(db_session)) == before

    async def test_duplicate_email_is_unavailable_and_creates_nothing(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        await service.register(EMAIL, STRONG_PASSWORD)
        before = (await count_users(db_session), await count_identities(db_session))

        with pytest.raises(RegistrationUnavailableError):
            await service.register("ALICE@example.com", "another strong passphrase")

        # No orphaned identity-less user is left behind by the failed attempt.
        assert (await count_users(db_session), await count_identities(db_session)) == before

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
        before = (await count_users(db_session), await count_identities(db_session))

        async def fail(*_: object) -> None:
            raise RuntimeError("session creation failed")

        monkeypatch.setattr(service._sessions, "start", fail)

        with pytest.raises(RuntimeError):
            await service.register(EMAIL, STRONG_PASSWORD)

        assert (await count_users(db_session), await count_identities(db_session)) == before


class TestLogin:
    async def test_success_starts_a_new_session(self, service: AuthService) -> None:
        _, first = await service.register(EMAIL, STRONG_PASSWORD)

        user, second = await service.login("ALICE@example.com", STRONG_PASSWORD)

        assert email_identity(user).email == EMAIL
        assert second.session_id != first.session_id

    async def test_login_resolves_the_identity_owner(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        registered, _ = await service.register(EMAIL, STRONG_PASSWORD)
        await service.register("bob@example.com", "another strong passphrase")

        user, pair = await service.login(EMAIL, STRONG_PASSWORD)

        assert user.id == registered.id
        assert pair.session_id is not None

    async def test_login_records_identity_last_used_at(
        self, service: AuthService, clock: FrozenClock
    ) -> None:
        await service.register(EMAIL, STRONG_PASSWORD)
        clock.advance(timedelta(hours=1))

        user, _ = await service.login(EMAIL, STRONG_PASSWORD)

        assert email_identity(user).last_used_at == clock.now

    async def test_failed_login_does_not_touch_last_used_at(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        user, _ = await service.register(EMAIL, STRONG_PASSWORD)

        with pytest.raises(InvalidCredentialsError):
            await service.login(EMAIL, "wrong passphrase entirely")

        await db_session.refresh(email_identity(user))
        assert email_identity(user).last_used_at is None

    async def test_user_with_linked_oauth_identity_still_password_logs_in(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        user, _ = await service.register(EMAIL, STRONG_PASSWORD)
        db_session.add(
            UserIdentity(user_id=user.id, provider=IdentityProvider.GOOGLE, subject="g-alice")
        )
        await db_session.flush()

        logged_in, _ = await service.login(EMAIL, STRONG_PASSWORD)

        assert logged_in.id == user.id

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

    async def test_inactive_user_still_pays_a_real_verification(
        self,
        service: AuthService,
        db_session: AsyncSession,
        hasher: PasswordHasher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Timing: an inactive account must not answer faster than an active one."""
        user, _ = await service.register(EMAIL, STRONG_PASSWORD)
        user.is_active = False
        await db_session.flush()
        verified: list[str] = []
        original = hasher.verify

        async def spy(password_hash: str, password: str) -> bool:
            verified.append("x")
            return await original(password_hash, password)

        monkeypatch.setattr(hasher, "verify", spy)

        with pytest.raises(InvalidCredentialsError):
            await service.login(EMAIL, STRONG_PASSWORD)

        assert verified == ["x"]

    async def test_non_email_accounts_cannot_password_login(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        await add_oauth_user(db_session, IdentityProvider.GOOGLE, "g-1", "gina@example.com")

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
            await add_oauth_user(db_session, IdentityProvider.APPLE, "a-1", "x@example.com")
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
        identity = email_identity(user)
        old_hash = identity.password_hash

        await build_service(db_session, test_settings, clock, strong).login(EMAIL, STRONG_PASSWORD)

        await db_session.refresh(identity)
        assert identity.password_hash != old_hash
        assert identity.password_hash is not None
        assert "$m=16,t=2,p=1$" in identity.password_hash

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
            guest_per_ip=GENEROUS_RATE_LIMITS.guest_per_ip,
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

    assert user.is_guest is True
    owned = select(func.count()).where(UserIdentity.user_id == user.id)
    assert (await db_session.execute(owned)).scalar_one() == 0


class TestGuest:
    async def test_creates_active_guest_with_no_identities_and_a_session(
        self, service: AuthService, db_session: AsyncSession
    ) -> None:
        user, pair = await service.sign_in_as_guest()

        assert (user.is_guest, user.is_active) == (True, True)
        assert user.identities == []
        owned = select(func.count()).where(UserIdentity.user_id == user.id)
        assert (await db_session.execute(owned)).scalar_one() == 0
        auth_session = await db_session.get(AuthSession, pair.session_id)
        assert auth_session is not None
        assert auth_session.user_id == user.id

    async def test_session_comes_from_session_service_for_the_new_user(
        self, service: AuthService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        started: list[uuid.UUID] = []
        original = service._sessions.start

        async def spy(user_id: uuid.UUID) -> TokenPair:
            started.append(user_id)
            return await original(user_id)

        monkeypatch.setattr(service._sessions, "start", spy)

        user, pair = await service.sign_in_as_guest()

        assert started == [user.id]
        assert pair.access_token
        assert pair.refresh_token

    async def test_user_and_session_are_created_atomically(
        self, service: AuthService, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        before = await count_users(db_session)

        async def fail(*_: object) -> None:
            raise RuntimeError("session creation failed")

        monkeypatch.setattr(service._sessions, "start", fail)

        with pytest.raises(RuntimeError):
            await service.sign_in_as_guest()

        assert await count_users(db_session) == before

    async def test_each_call_is_a_new_user(self, service: AuthService) -> None:
        first, first_pair = await service.sign_in_as_guest()
        second, second_pair = await service.sign_in_as_guest()

        assert first.id != second.id
        assert first_pair.session_id != second_pair.session_id

    async def test_later_upgrade_keeps_the_same_user_and_sessions(
        self, service: AuthService, db_session: AsyncSession, hasher: PasswordHasher
    ) -> None:
        """Ownership is by user_id: linking an identity later keeps the guest's data attached."""
        user, pair = await service.sign_in_as_guest()

        identity = await IdentityService(db_session).link(
            user.id,
            IdentityProvider.EMAIL,
            EMAIL,
            password_hash=await hasher.hash(STRONG_PASSWORD),
        )
        user.is_guest = False
        await db_session.commit()

        assert identity.user_id == user.id
        auth_session = await db_session.get(AuthSession, pair.session_id)
        assert auth_session is not None
        assert auth_session.user_id == user.id
        logged_in, _ = await service.login(EMAIL, STRONG_PASSWORD)
        assert logged_in.id == user.id
