import logging
import uuid
from datetime import timedelta
from typing import Any

import jwt
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.passwords import PasswordHasher
from app.core.rate_limit import DEFAULT_AUTH_RATE_LIMITS
from app.core.tokens import AccessTokenService
from app.models.auth_session import AuthSession
from app.models.user import User
from tests.support.auth import API, bearer, login, register, registered_tokens
from tests.support.clock import FrozenClock
from tests.support.passwords import STRONG_PASSWORD

UNAUTHORIZED = {"error": {"code": "unauthorized", "message": "Authentication required"}}
PROTECTED = [("GET", f"{API}/me"), ("POST", f"{API}/logout-all")]


def client_from(app: FastAPI, ip: str = "203.0.113.7") -> AsyncClient:
    transport = ASGITransport(app=app, raise_app_exceptions=False, client=(ip, 40000))
    return AsyncClient(transport=transport, base_url="http://test")


async def call(client: AsyncClient, method: str, path: str, **kwargs: Any) -> Any:
    return await client.request(method, path, **kwargs)


def assert_unauthorized(response: Any) -> None:
    assert response.status_code == 401
    assert response.json() == UNAUTHORIZED
    assert response.headers["www-authenticate"] == "Bearer"


class TestBearerExtraction:
    @pytest.mark.parametrize(("method", "path"), PROTECTED)
    async def test_missing_header(self, auth_client: AsyncClient, method: str, path: str) -> None:
        assert_unauthorized(await call(auth_client, method, path))

    @pytest.mark.parametrize(
        "header",
        [
            "",
            "Bearer",
            "Bearer ",
            "Basic dXNlcjpwYXNz",
            "Token abc",
            "Bearer a b",
            "Bearer  {token}",  # double space
            "{token}",  # scheme missing
            "Bearer {token}, Bearer {token}",
        ],
    )
    async def test_malformed_authorization_header(
        self, auth_client: AsyncClient, header: str
    ) -> None:
        token = (await registered_tokens(auth_client))["access_token"]

        response = await auth_client.get(
            f"{API}/me", headers={"Authorization": header.format(token=token)}
        )

        assert_unauthorized(response)

    async def test_scheme_is_case_insensitive(self, auth_client: AsyncClient) -> None:
        token = (await registered_tokens(auth_client))["access_token"]

        response = await auth_client.get(f"{API}/me", headers={"Authorization": f"bearer {token}"})

        assert response.status_code == 200

    async def test_token_in_query_string_is_ignored(self, auth_client: AsyncClient) -> None:
        token = (await registered_tokens(auth_client))["access_token"]

        assert_unauthorized(await auth_client.get(f"{API}/me", params={"access_token": token}))

    async def test_refresh_token_is_not_an_access_token(self, auth_client: AsyncClient) -> None:
        tokens = await registered_tokens(auth_client)

        assert_unauthorized(
            await auth_client.get(f"{API}/me", headers=bearer(tokens["refresh_token"]))
        )


class TestAccessTokenValidation:
    async def test_invalid_signature(
        self, auth_client: AsyncClient, test_settings: Settings
    ) -> None:
        tokens = await registered_tokens(auth_client)
        claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
        forged = jwt.encode(claims, "attacker-chosen-secret-that-is-long-enough!!", "HS256")

        assert_unauthorized(await auth_client.get(f"{API}/me", headers=bearer(forged)))

    async def test_expired_token(
        self, auth_client: AsyncClient, auth_app: FastAPI, test_settings: Settings
    ) -> None:
        clock = FrozenClock()
        auth_app.state.clock = clock
        tokens = await registered_tokens(auth_client)
        clock.advance(timedelta(minutes=16))

        assert_unauthorized(
            await auth_client.get(f"{API}/me", headers=bearer(tokens["access_token"]))
        )

    async def test_garbage_token(self, auth_client: AsyncClient) -> None:
        assert_unauthorized(await auth_client.get(f"{API}/me", headers=bearer("x" * 5000)))

    async def test_failures_are_indistinguishable(
        self, auth_client: AsyncClient, test_settings: Settings, db_session: AsyncSession
    ) -> None:
        tokens = await registered_tokens(auth_client)
        expired = (
            AccessTokenService(test_settings, clock=FrozenClock())
            .issue(user_id=uuid.UUID(tokens["user"]["id"]), session_id=uuid.uuid7())
            .token
        )
        cases = [
            None,
            "Basic x",
            "Bearer junk",
            f"Bearer {expired}",
            f"Bearer {tokens['refresh_token']}",
        ]

        responses = []
        for header in cases:
            headers = {"Authorization": header} if header else {}
            r = await auth_client.get(f"{API}/me", headers=headers)
            responses.append((r.status_code, r.text, r.headers.get("www-authenticate")))

        assert len(set(responses)) == 1


class TestPrincipalState:
    async def test_revoked_session(self, auth_client: AsyncClient) -> None:
        tokens = await registered_tokens(auth_client)
        await auth_client.post(f"{API}/logout", headers=bearer(tokens["access_token"]))

        assert_unauthorized(
            await auth_client.get(f"{API}/me", headers=bearer(tokens["access_token"]))
        )

    async def test_inactive_user(self, auth_client: AsyncClient, db_session: AsyncSession) -> None:
        tokens = await registered_tokens(auth_client)
        await db_session.execute(update(User).values(is_active=False))

        for method, path in PROTECTED:
            assert_unauthorized(
                await call(auth_client, method, path, headers=bearer(tokens["access_token"]))
            )
        login_response = await login(auth_client)
        assert login_response.status_code == 401
        assert login_response.json()["error"]["code"] == "invalid_credentials"

    async def test_deleted_user(self, auth_client: AsyncClient, db_session: AsyncSession) -> None:
        tokens = await registered_tokens(auth_client)
        await db_session.execute(delete(User).where(User.id == uuid.UUID(tokens["user"]["id"])))

        assert_unauthorized(
            await auth_client.get(f"{API}/me", headers=bearer(tokens["access_token"]))
        )
        refresh = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert refresh.status_code == 401
        # Logout stays idempotent and harmless.
        logout = await auth_client.post(f"{API}/logout", headers=bearer(tokens["access_token"]))
        assert logout.status_code == 204

    async def test_session_past_absolute_expiry(
        self, auth_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        tokens = await registered_tokens(auth_client)
        await db_session.execute(
            update(AuthSession).values(expires_at=AuthSession.created_at - timedelta(seconds=1))
        )

        assert_unauthorized(
            await auth_client.get(f"{API}/me", headers=bearer(tokens["access_token"]))
        )


class TestCrossUser:
    async def test_me_returns_only_the_caller(self, auth_client: AsyncClient) -> None:
        alice = await registered_tokens(auth_client, "alice@example.com")
        bob = await registered_tokens(auth_client, "bob@example.com")

        me = await auth_client.get(f"{API}/me", headers=bearer(bob["access_token"]))

        assert me.json()["id"] == bob["user"]["id"]
        assert alice["user"]["email"] not in me.text

    async def test_token_pairing_one_users_id_with_anothers_session_is_rejected(
        self, auth_client: AsyncClient, test_settings: Settings
    ) -> None:
        """Defence in depth: even a correctly signed token cannot borrow another user's session."""
        alice = await registered_tokens(auth_client, "alice@example.com")
        bob = await registered_tokens(auth_client, "bob@example.com")
        access = AccessTokenService(test_settings)
        bobs_session = access.decode(bob["access_token"]).session_id
        mixed = access.issue(user_id=uuid.UUID(alice["user"]["id"]), session_id=bobs_session)

        assert_unauthorized(await auth_client.get(f"{API}/me", headers=bearer(mixed.token)))
        logout = await auth_client.post(f"{API}/logout", headers=bearer(mixed.token))
        assert logout.status_code == 204
        # Bob's session survived the attempt.
        assert (
            await auth_client.get(f"{API}/me", headers=bearer(bob["access_token"]))
        ).status_code == 200

    async def test_logout_all_leaves_other_users_alone(self, auth_client: AsyncClient) -> None:
        alice = await registered_tokens(auth_client, "alice@example.com")
        bob = await registered_tokens(auth_client, "bob@example.com")

        await auth_client.post(f"{API}/logout-all", headers=bearer(alice["access_token"]))

        assert (
            await auth_client.get(f"{API}/me", headers=bearer(bob["access_token"]))
        ).status_code == 200
        refresh = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": bob["refresh_token"]}
        )
        assert refresh.status_code == 200

    async def test_logout_does_not_affect_other_users(self, auth_client: AsyncClient) -> None:
        alice = await registered_tokens(auth_client, "alice@example.com")
        bob = await registered_tokens(auth_client, "bob@example.com")

        await auth_client.post(f"{API}/logout", headers=bearer(alice["access_token"]))

        assert (
            await auth_client.get(f"{API}/me", headers=bearer(bob["access_token"]))
        ).status_code == 200


class TestEnumeration:
    async def test_unknown_email_and_wrong_password_are_identical(
        self, auth_client: AsyncClient
    ) -> None:
        await register(auth_client)

        unknown = await login(auth_client, email="nobody@example.com")
        wrong = await login(auth_client, password="wrong passphrase entirely")

        assert unknown.status_code == wrong.status_code == 401
        assert unknown.content == wrong.content
        strip = {"date", "content-length"}
        assert {k: v for k, v in unknown.headers.items() if k not in strip} == {
            k: v for k, v in wrong.headers.items() if k not in strip
        }

    async def test_duplicate_registration_body_reveals_no_account_detail(
        self, auth_client: AsyncClient
    ) -> None:
        await register(auth_client)

        response = await register(auth_client, password="another strong passphrase")

        assert "alice" not in response.text
        assert "exist" not in response.text.lower()


class TestRateLimiting:
    @pytest.fixture
    async def limited_app(self, auth_app: FastAPI) -> FastAPI:
        auth_app.state.rate_limits = DEFAULT_AUTH_RATE_LIMITS
        return auth_app

    async def test_login_per_ip(self, limited_app: FastAPI) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.login_per_ip.limit
        async with client_from(limited_app) as client:
            # Different (unknown) accounts so only the per-IP rule can trigger.
            statuses = [
                (await login(client, email=f"user{i}@example.com")).status_code
                for i in range(limit + 1)
            ]

        assert statuses[:limit] == [401] * limit
        assert statuses[limit] == 429

    async def test_login_per_account_across_ips(self, limited_app: FastAPI) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.login_per_account.limit
        statuses = []
        for i in range(limit + 1):
            async with client_from(limited_app, ip=f"198.51.100.{i + 1}") as client:
                statuses.append((await login(client, password="wrong passphrase")).status_code)

        assert statuses[-1] == 429

    async def test_register_per_ip(self, limited_app: FastAPI) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.register_per_ip.limit
        async with client_from(limited_app) as client:
            statuses = [
                (await register(client, email=f"new{i}@example.com")).status_code
                for i in range(limit + 1)
            ]

        assert statuses[:limit] == [201] * limit
        assert statuses[limit] == 429

    async def test_refresh_per_ip(self, limited_app: FastAPI) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.refresh_per_ip.limit
        async with client_from(limited_app) as client:
            statuses = [
                (await client.post(f"{API}/refresh", json={"refresh_token": "x"})).status_code
                for _ in range(limit + 1)
            ]

        assert statuses[limit] == 429

    async def test_429_is_safe_and_has_retry_after(self, limited_app: FastAPI) -> None:
        async with client_from(limited_app) as client:
            for i in range(DEFAULT_AUTH_RATE_LIMITS.login_per_ip.limit):
                await login(client, email=f"user{i}@example.com")
            response = await login(client)

        assert response.status_code == 429
        assert response.json() == {
            "error": {"code": "too_many_requests", "message": "Too many requests"}
        }
        assert int(response.headers["retry-after"]) > 0

    async def test_limits_are_per_client(self, limited_app: FastAPI) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.login_per_ip.limit
        async with client_from(limited_app, ip="192.0.2.1") as client:
            for i in range(limit + 1):
                await login(client, email=f"user{i}@example.com")
        async with client_from(limited_app, ip="192.0.2.2") as other:
            assert (await login(other, email="someone@example.com")).status_code == 401


class TestNoLeaks:
    async def test_password_hash_never_returned(self, auth_client: AsyncClient) -> None:
        responses = [await register(auth_client), await login(auth_client)]
        tokens = responses[0].json()
        responses.append(await auth_client.get(f"{API}/me", headers=bearer(tokens["access_token"])))
        responses.append(
            await auth_client.post(
                f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}
            )
        )

        for response in responses:
            assert "password" not in response.text
            assert "$argon2" not in response.text

    async def test_me_never_returns_tokens(self, auth_client: AsyncClient) -> None:
        tokens = await registered_tokens(auth_client)

        me = await auth_client.get(f"{API}/me", headers=bearer(tokens["access_token"]))

        assert tokens["refresh_token"] not in me.text
        assert tokens["access_token"] not in me.text

    async def test_credentials_and_tokens_are_never_logged(
        self, auth_client: AsyncClient, db_session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        email = "secret.person@example.com"
        registered = (await register(auth_client, email=email)).json()
        await login(auth_client, email=email, password="wrong passphrase entirely")
        logged_in = (await login(auth_client, email=email)).json()
        refreshed = (
            await auth_client.post(
                f"{API}/refresh", json={"refresh_token": logged_in["refresh_token"]}
            )
        ).json()
        await auth_client.post(f"{API}/refresh", json={"refresh_token": logged_in["refresh_token"]})
        await auth_client.get(f"{API}/me", headers=bearer(refreshed["access_token"]))
        await auth_client.post(f"{API}/logout", headers=bearer(registered["access_token"]))
        user = await db_session.get(User, uuid.UUID(registered["user"]["id"]))
        assert user is not None
        (identity,) = user.identities

        logged = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
        sensitive = [
            STRONG_PASSWORD,
            "wrong passphrase entirely",
            email,
            "secret.person",
            identity.password_hash or "",
        ]
        for body in (registered, logged_in, refreshed):
            sensitive += [body["access_token"], body["refresh_token"]]
        for value in sensitive:
            assert value not in logged

    @pytest.mark.parametrize(
        "payload",
        [
            {"email": "alice@example.com' OR '1'='1", "password": STRONG_PASSWORD},
            {"email": "alice@example.com", "password": "' OR '1'='1' --"},
            {"email": "alice@example.com", "password": "x'); DROP TABLE users; --"},
        ],
    )
    async def test_sql_injection_payloads_fail_safely(
        self, auth_client: AsyncClient, payload: dict[str, str]
    ) -> None:
        await register(auth_client)

        response = await auth_client.post(f"{API}/login", json=payload)

        assert response.status_code in (401, 422)
        assert (await login(auth_client)).status_code == 200

    async def test_oversized_password_is_rejected_before_hashing(
        self, auth_client: AsyncClient, auth_app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hasher: PasswordHasher = auth_app.state.password_hasher

        async def must_not_hash(*_: object) -> Any:
            raise AssertionError("oversized input reached the hasher")

        monkeypatch.setattr(hasher, "hash", must_not_hash)
        monkeypatch.setattr(hasher, "verify", must_not_hash)
        monkeypatch.setattr(hasher, "verify_dummy", must_not_hash)

        for endpoint in ("register", "login"):
            response = await auth_client.post(
                f"{API}/{endpoint}", json={"email": "a@example.com", "password": "x" * 100_000}
            )
            assert response.status_code == 422
            assert "xxxx" not in response.text

    async def test_internal_errors_are_generic(
        self, auth_client: AsyncClient, auth_app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hasher: PasswordHasher = auth_app.state.password_hasher

        async def boom(*_: object) -> Any:
            raise RuntimeError("psycopg.OperationalError: password=hunter2 host=10.0.0.5")

        monkeypatch.setattr(hasher, "hash", boom)

        response = await register(auth_client)

        assert response.status_code == 500
        assert response.json() == {
            "error": {"code": "internal_error", "message": "Internal server error"}
        }
        assert "hunter2" not in response.text
