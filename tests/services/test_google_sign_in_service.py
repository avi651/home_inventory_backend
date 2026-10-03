"""GoogleSignInService: OAuth state lifecycle and Google identity -> user resolution (D1)."""

import hashlib
import logging
import uuid
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.tokens import AccessTokenService
from app.exceptions.errors import (
    AccountLinkRequiredError,
    OAuthSignInFailedError,
    ProviderUnavailableError,
)
from app.models.auth_session import AuthSession
from app.models.oauth_login_attempt import OAuthLoginAttempt
from app.models.user import User
from app.models.user_identity import IdentityProvider, UserIdentity
from app.services.google_sign_in_service import (
    OAUTH_ATTEMPT_LIFETIME,
    GoogleSignInService,
    OAuthStart,
)
from app.services.identity_service import IdentityService
from app.services.session_service import SessionService
from tests.support.clock import FrozenClock
from tests.support.google import CLIENT_SECRET, FakeGoogle

FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def google(clock: FrozenClock) -> FakeGoogle:
    return FakeGoogle(clock=clock)


@pytest.fixture
def service(
    db_session: AsyncSession, test_settings: Settings, clock: FrozenClock, google: FakeGoogle
) -> GoogleSignInService:
    sessions = SessionService(
        db_session, AccessTokenService(test_settings, clock=clock), test_settings, clock=clock
    )
    return GoogleSignInService(db_session, google=google.client(), sessions=sessions, clock=clock)


async def count(db: AsyncSession, model: type[Any], *where: Any) -> int:
    return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def query_of(start: OAuthStart) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(start.authorization_url).query).items()}


async def sign_in(service: GoogleSignInService, google: FakeGoogle) -> Any:
    start = await service.start()
    code, state = google.authorize(start.authorization_url)
    return await service.complete(code=code, state=state, attempt_token=start.attempt_token)


class TestState:
    async def test_start_issues_random_state_nonce_and_pkce(
        self, service: GoogleSignInService
    ) -> None:
        starts = [await service.start() for _ in range(3)]

        queries = [query_of(s) for s in starts]
        for key in ("state", "nonce", "code_challenge"):
            values = {q[key] for q in queries}
            assert len(values) == 3
            assert all(len(v) >= 43 for v in values)  # >= 256 bits, base64url
        assert len({s.attempt_token for s in starts}) == 3
        assert all(len(s.attempt_token) >= 43 for s in starts)
        assert {s.expires_in for s in starts} == {int(OAUTH_ATTEMPT_LIFETIME.total_seconds())}

    async def test_only_hashes_are_stored(
        self, service: GoogleSignInService, db_session: AsyncSession
    ) -> None:
        start = await service.start()
        query = query_of(start)

        (attempt,) = (await db_session.execute(select(OAuthLoginAttempt))).scalars().all()

        assert attempt.provider is IdentityProvider.GOOGLE
        assert attempt.state_hash == sha256(query["state"])
        assert attempt.binding_hash == sha256(start.attempt_token)
        assert attempt.nonce_hash == sha256(query["nonce"])
        stored = repr(attempt) + str(vars(attempt))
        for raw in (query["state"], query["nonce"], start.attempt_token):
            assert raw not in stored

    async def test_valid_round_trip_signs_in(
        self, service: GoogleSignInService, google: FakeGoogle
    ) -> None:
        user, pair = await sign_in(service, google)

        assert pair.access_token
        assert user.id is not None

    async def test_state_is_single_use(
        self, service: GoogleSignInService, google: FakeGoogle
    ) -> None:
        start = await service.start()
        code, state = google.authorize(start.authorization_url)
        await service.complete(code=code, state=state, attempt_token=start.attempt_token)
        replay_code, _ = google.authorize(start.authorization_url)  # even with a fresh code

        with pytest.raises(OAuthSignInFailedError):
            await service.complete(code=replay_code, state=state, attempt_token=start.attempt_token)

    async def test_failed_attempt_still_consumes_the_state(
        self, service: GoogleSignInService, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        start = await service.start()
        code, state = google.authorize(start.authorization_url)
        google.token_response = lambda: httpx.Response(500)

        with pytest.raises(ProviderUnavailableError):
            await service.complete(code=code, state=state, attempt_token=start.attempt_token)
        google.token_response = None

        with pytest.raises(OAuthSignInFailedError):
            await service.complete(code=code, state=state, attempt_token=start.attempt_token)
        assert await count(db_session, OAuthLoginAttempt) == 0

    async def test_expired_state_is_rejected_without_calling_google(
        self, service: GoogleSignInService, google: FakeGoogle, clock: FrozenClock
    ) -> None:
        start = await service.start()
        code, state = google.authorize(start.authorization_url)
        clock.advance(OAUTH_ATTEMPT_LIFETIME + timedelta(seconds=1))

        with pytest.raises(OAuthSignInFailedError):
            await service.complete(code=code, state=state, attempt_token=start.attempt_token)
        assert google.token_requests == []

    @pytest.mark.parametrize("tamper", ["state", "attempt_token"])
    async def test_mismatched_state_or_binding_is_rejected(
        self, service: GoogleSignInService, google: FakeGoogle, tamper: str
    ) -> None:
        start = await service.start()
        code, state = google.authorize(start.authorization_url)
        values = {"code": code, "state": state, "attempt_token": start.attempt_token}
        values[tamper] = values[tamper][:-1] + ("A" if values[tamper][-1] != "A" else "B")

        with pytest.raises(OAuthSignInFailedError):
            await service.complete(**values)
        assert google.token_requests == []

    async def test_another_clients_attempt_token_cannot_complete_the_login(
        self, service: GoogleSignInService, google: FakeGoogle
    ) -> None:
        """A stolen code+state (e.g. intercepted redirect) is useless without the binding."""
        victim = await service.start()
        attacker = await service.start()
        code, state = google.authorize(victim.authorization_url)

        with pytest.raises(OAuthSignInFailedError):
            await service.complete(code=code, state=state, attempt_token=attacker.attempt_token)

    async def test_code_from_another_attempt_is_rejected(
        self, service: GoogleSignInService, google: FakeGoogle
    ) -> None:
        """PKCE: a code issued for attempt A cannot be redeemed through attempt B."""
        first = await service.start()
        second = await service.start()
        code_for_first, _ = google.authorize(first.authorization_url)
        _, second_state = google.authorize(second.authorization_url)

        with pytest.raises(OAuthSignInFailedError):
            await service.complete(
                code=code_for_first, state=second_state, attempt_token=second.attempt_token
            )

    async def test_expired_attempts_are_purged(
        self, service: GoogleSignInService, db_session: AsyncSession, clock: FrozenClock
    ) -> None:
        await service.start()
        clock.advance(OAUTH_ATTEMPT_LIFETIME + timedelta(seconds=1))

        await service.start()

        assert await count(db_session, OAuthLoginAttempt) == 1

    async def test_state_code_and_tokens_are_never_logged(
        self,
        service: GoogleSignInService,
        google: FakeGoogle,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        start = await service.start()
        code, state = google.authorize(start.authorization_url)
        user, pair = await service.complete(
            code=code, state=state, attempt_token=start.attempt_token
        )
        with pytest.raises(OAuthSignInFailedError):
            await service.complete(code=code, state=state, attempt_token=start.attempt_token)

        logged = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
        query = query_of(start)
        for secret in (
            state,
            code,
            query["nonce"],
            query["code_challenge"],
            start.attempt_token,
            pair.access_token,
            pair.refresh_token,
            CLIENT_SECRET,
            google.subject,
            "gina@example.com",
            "ya29.",
            "eyJ",
        ):
            assert secret not in logged
        assert f"user_id={user.id}" in logged


class TestNewUser:
    async def test_first_sign_in_creates_user_identity_and_session(
        self,
        service: GoogleSignInService,
        google: FakeGoogle,
        db_session: AsyncSession,
        clock: FrozenClock,
    ) -> None:
        user, pair = await sign_in(service, google)

        assert (user.is_guest, user.is_active) == (False, True)
        (identity,) = user.identities
        assert identity.provider is IdentityProvider.GOOGLE
        assert identity.subject == google.subject
        assert identity.email == "gina@example.com"
        assert identity.email_verified is True
        assert identity.password_hash is None
        assert identity.last_used_at == clock.now
        auth_session = await db_session.get(AuthSession, pair.session_id)
        assert auth_session is not None
        assert auth_session.user_id == user.id

    async def test_unverified_email_is_not_stored(
        self, service: GoogleSignInService, google: FakeGoogle
    ) -> None:
        google.email_verified = False

        user, _ = await sign_in(service, google)

        (identity,) = user.identities
        assert (identity.email, identity.email_verified) == (None, False)

    async def test_unverified_email_matching_an_account_creates_a_separate_user(
        self, service: GoogleSignInService, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        owner = await add_email_user(db_session, "gina@example.com")
        google.email_verified = False

        user, _ = await sign_in(service, google)

        assert user.id != owner.id
        assert await count(db_session, UserIdentity, UserIdentity.user_id == owner.id) == 1

    async def test_user_identity_and_session_are_created_atomically(
        self,
        service: GoogleSignInService,
        google: FakeGoogle,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = [await count(db_session, m) for m in (User, UserIdentity, AuthSession)]

        async def fail(*_: object) -> None:
            raise RuntimeError("session creation failed")

        monkeypatch.setattr(service._sessions, "start", fail)

        with pytest.raises(RuntimeError):
            await sign_in(service, google)

        assert [await count(db_session, m) for m in (User, UserIdentity, AuthSession)] == before

    @pytest.mark.parametrize(
        "token_response",
        [lambda: httpx.Response(400, json={"error": "invalid_grant"}), lambda: httpx.Response(503)],
    )
    async def test_provider_failure_creates_nothing(
        self,
        service: GoogleSignInService,
        google: FakeGoogle,
        db_session: AsyncSession,
        token_response: Any,
    ) -> None:
        before = await count(db_session, User)
        google.token_response = token_response

        with pytest.raises((OAuthSignInFailedError, ProviderUnavailableError)):
            await sign_in(service, google)

        assert await count(db_session, User) == before


class TestExistingIdentity:
    async def test_repeat_sign_in_resolves_the_same_user(
        self, service: GoogleSignInService, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        first, first_pair = await sign_in(service, google)
        users = await count(db_session, User)

        second, second_pair = await sign_in(service, google)

        assert second.id == first.id
        assert second_pair.session_id != first_pair.session_id
        assert await count(db_session, User) == users
        assert await count(db_session, UserIdentity, UserIdentity.user_id == first.id) == 1

    async def test_google_sub_is_the_key_not_the_email(
        self, service: GoogleSignInService, google: FakeGoogle
    ) -> None:
        first, _ = await sign_in(service, google)
        google.email = "renamed@example.com"

        second, _ = await sign_in(service, google)

        assert second.id == first.id

    async def test_last_used_at_is_updated(
        self,
        service: GoogleSignInService,
        google: FakeGoogle,
        clock: FrozenClock,
        db_session: AsyncSession,
    ) -> None:
        user, _ = await sign_in(service, google)
        clock.advance(timedelta(days=2))

        await sign_in(service, google)

        (identity,) = (
            await db_session.execute(select(UserIdentity).where(UserIdentity.user_id == user.id))
        ).scalars()
        await db_session.refresh(identity)
        assert identity.last_used_at == clock.now

    async def test_inactive_user_is_rejected_and_gets_no_session(
        self, service: GoogleSignInService, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        user, _ = await sign_in(service, google)
        user.is_active = False
        await db_session.commit()
        sessions = await count(db_session, AuthSession, AuthSession.user_id == user.id)

        with pytest.raises(OAuthSignInFailedError):
            await sign_in(service, google)

        assert await count(db_session, AuthSession, AuthSession.user_id == user.id) == sessions

    async def test_sign_in_for_an_existing_guest_linked_identity(
        self, service: GoogleSignInService, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        """An identity linked explicitly (future linking API) signs that same user in."""
        owner = User()
        db_session.add(owner)
        await db_session.flush()
        await IdentityService(db_session).link(owner.id, IdentityProvider.GOOGLE, google.subject)

        user, _ = await sign_in(service, google)

        assert user.id == owner.id


async def add_email_user(db: AsyncSession, email: str) -> User:
    user = User()
    db.add(user)
    await db.flush()
    await IdentityService(db).link(user.id, IdentityProvider.EMAIL, email, password_hash=FAKE_HASH)
    return user


class TestNoImplicitLinking:
    async def test_verified_email_of_a_password_account_requires_explicit_linking(
        self, service: GoogleSignInService, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        owner = await add_email_user(db_session, "gina@example.com")
        users = await count(db_session, User)
        google.email = "Gina@Example.com"

        with pytest.raises(AccountLinkRequiredError):
            await sign_in(service, google)

        assert await count(db_session, User) == users
        assert await count(db_session, UserIdentity, UserIdentity.user_id == owner.id) == 1
        assert (
            await count(db_session, UserIdentity, UserIdentity.provider == IdentityProvider.GOOGLE)
            == 0
        )

    async def test_same_email_different_google_sub_does_not_auto_link(
        self, service: GoogleSignInService, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        first, _ = await sign_in(service, google)
        google.subject = "999999999999999999999"

        with pytest.raises(AccountLinkRequiredError):
            await sign_in(service, google)

        google_identities = (
            await db_session.execute(
                select(UserIdentity.user_id, UserIdentity.subject).where(
                    UserIdentity.provider == IdentityProvider.GOOGLE
                )
            )
        ).all()
        assert [tuple(r) for r in google_identities] == [(first.id, "108234567890123456789")]

    async def test_existing_identity_signs_in_even_if_email_now_matches_another_account(
        self, service: GoogleSignInService, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        user, _ = await sign_in(service, google)
        await add_email_user(db_session, "new@example.com")
        google.email = "new@example.com"

        again, _ = await sign_in(service, google)

        assert again.id == user.id

    async def test_never_signs_in_a_password_account_by_email(
        self, service: GoogleSignInService, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        owner = await add_email_user(db_session, "gina@example.com")
        google.email_verified = False

        user, pair = await sign_in(service, google)

        assert user.id != owner.id
        auth_session = await db_session.get(AuthSession, pair.session_id)
        assert auth_session is not None
        assert auth_session.user_id != owner.id
        assert isinstance(user.id, uuid.UUID)


class TestConcurrentFirstSignIn:
    async def test_losing_the_race_signs_in_the_winner_instead_of_failing(
        self,
        service: GoogleSignInService,
        google: FakeGoogle,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another request linked this sub between our lookup and our insert."""
        winner = User()
        db_session.add(winner)
        await db_session.flush()
        await IdentityService(db_session).link(winner.id, IdentityProvider.GOOGLE, google.subject)
        await db_session.commit()
        users_before = await count(db_session, User)
        original = service._identities.resolve
        calls: list[str] = []

        async def stale_first_lookup(provider: IdentityProvider, subject: str) -> Any:
            calls.append(subject)
            return None if len(calls) == 1 else await original(provider, subject)

        monkeypatch.setattr(service._identities, "resolve", stale_first_lookup)
        google.email = None  # skip the email check so the insert itself hits the conflict

        user, _ = await sign_in(service, google)

        assert user.id == winner.id
        assert len(calls) == 2
        assert await count(db_session, User) == users_before
