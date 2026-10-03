"""POST /auth/{google,apple}/start and POST /auth/{google,apple}/callback (Steps 8-9).

Every test runs once per provider through the real routes, dependencies and error handlers.
"""

import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rate_limit import DEFAULT_AUTH_RATE_LIMITS
from app.models.user import User
from app.services.apple_oauth import AppleOAuthClient
from app.services.google_oauth import GoogleOAuthClient
from tests.support.apple import FakeApple, team_key_pem
from tests.support.auth import API, bearer, registered_tokens
from tests.support.clock import FrozenClock
from tests.support.google import FakeGoogle
from tests.support.oidc_fake import FakeOidcProvider

PROVIDERS = ["google", "apple"]
OAUTH_FAILED = {
    "error": {"code": "oauth_failed", "message": "Unable to sign in with this provider"}
}
UNAVAILABLE = {
    "error": {"code": "provider_unavailable", "message": "Sign-in provider is unavailable"}
}
LINK_REQUIRED = {
    "error": {
        "code": "account_link_required",
        "message": "Sign in with your existing account to link this sign-in method",
    }
}
FAKES: dict[str, type[FakeOidcProvider]] = {"google": FakeGoogle, "apple": FakeApple}


def start_url(name: str) -> str:
    return f"{API}/{name}/start"


def callback_url(name: str) -> str:
    return f"{API}/{name}/callback"


@pytest.fixture(params=PROVIDERS)
def idp(request: pytest.FixtureRequest, auth_app: FastAPI) -> FakeOidcProvider:
    # Real-time-ish frozen clock shared by the app and the fake provider.
    clock = FrozenClock(datetime.now(UTC).replace(microsecond=0))
    auth_app.state.clock = clock
    fake = FAKES[request.param](clock=clock)
    setattr(auth_app.state, f"{request.param}_oauth", fake.client())
    return fake


def name_of(idp: FakeOidcProvider) -> str:
    return idp.provider.value


async def start(client: AsyncClient, idp: FakeOidcProvider) -> dict[str, Any]:
    response = await client.post(start_url(name_of(idp)))
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def complete(client: AsyncClient, idp: FakeOidcProvider) -> httpx.Response:
    started = await start(client, idp)
    code, state = idp.authorize(started["authorization_url"])
    return await client.post(
        callback_url(name_of(idp)),
        json={"code": code, "state": state, "attempt_token": started["attempt_token"]},
    )


class TestStart:
    async def test_returns_authorization_url_and_binding_token(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        response = await auth_client.post(start_url(name_of(idp)))

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"authorization_url", "attempt_token", "expires_in"}
        assert body["authorization_url"].startswith(idp.AUTHORIZATION_URL + "?")
        assert body["attempt_token"] not in body["authorization_url"]
        assert body["expires_in"] == 600
        assert response.headers["cache-control"] == "no-store"

    async def test_get_is_not_allowed(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        assert (await auth_client.get(start_url(name_of(idp)))).status_code == 405
        assert (await auth_client.get(callback_url(name_of(idp)))).status_code == 405


class TestCallback:
    async def test_new_user_gets_the_standard_auth_response(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        response = await complete(auth_client, idp)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"access_token", "refresh_token", "token_type", "expires_in", "user"}
        assert body["user"]["auth_provider"] == name_of(idp)
        assert body["user"]["email"] == "gina@example.com"
        assert body["user"]["is_active"] is True

    async def test_tokens_work_with_existing_session_endpoints(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        body = (await complete(auth_client, idp)).json()

        me = await auth_client.get(f"{API}/me", headers=bearer(body["access_token"]))
        rotated = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": body["refresh_token"]}
        )
        reuse = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": body["refresh_token"]}
        )
        out = await auth_client.post(
            f"{API}/logout", headers=bearer(rotated.json()["access_token"])
        )

        assert me.json() == body["user"]
        assert rotated.status_code == 200
        assert reuse.status_code == 401
        assert out.status_code == 204

    async def test_repeat_sign_in_returns_the_same_user(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        first = (await complete(auth_client, idp)).json()
        second = (await complete(auth_client, idp)).json()

        assert second["user"]["id"] == first["user"]["id"]

    @pytest.mark.parametrize(
        "extra",
        [
            {"sub": "attacker"},
            {"email": "victim@example.com"},
            {"id_token": "eyJ.x.y"},
            {"user": '{"email": "victim@example.com"}'},  # Apple's first-login form field
            {"code_verifier": "v" * 64},
        ],
    )
    async def test_client_supplied_identity_or_verifier_is_refused(
        self, auth_client: AsyncClient, idp: FakeOidcProvider, extra: dict[str, str]
    ) -> None:
        started = await start(auth_client, idp)
        code, state = idp.authorize(started["authorization_url"])

        response = await auth_client.post(
            callback_url(name_of(idp)),
            json={"code": code, "state": state, "attempt_token": started["attempt_token"], **extra},
        )

        assert response.status_code == 422
        assert idp.token_requests == []

    @pytest.mark.parametrize("missing", ["code", "state", "attempt_token"])
    async def test_all_fields_are_required(
        self, auth_client: AsyncClient, idp: FakeOidcProvider, missing: str
    ) -> None:
        body = {"code": "c", "state": "s", "attempt_token": "t"}
        del body[missing]

        response = await auth_client.post(callback_url(name_of(idp)), json=body)

        assert response.status_code == 422

    async def test_replayed_callback_is_rejected(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        started = await start(auth_client, idp)
        code, state = idp.authorize(started["authorization_url"])
        payload = {"code": code, "state": state, "attempt_token": started["attempt_token"]}
        first = await auth_client.post(callback_url(name_of(idp)), json=payload)

        replay = await auth_client.post(callback_url(name_of(idp)), json=payload)

        assert first.status_code == 200
        assert replay.status_code == 401
        assert replay.json() == OAUTH_FAILED

    async def test_unknown_state_is_a_generic_401(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        response = await auth_client.post(
            callback_url(name_of(idp)), json={"code": "c", "state": "forged", "attempt_token": "t"}
        )

        assert response.status_code == 401
        assert response.json() == OAUTH_FAILED

    async def test_provider_outage_is_a_generic_503(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        idp.token_response = lambda: httpx.Response(
            500, json={"error": "backendError", "detail": "provider-internal-detail"}
        )

        response = await complete(auth_client, idp)

        assert response.status_code == 503
        assert response.json() == UNAVAILABLE
        assert "provider-internal-detail" not in response.text

    async def test_invalid_id_token_is_a_generic_401(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        idp.claim_overrides = {"aud": "someone-else"}

        response = await complete(auth_client, idp)

        assert response.status_code == 401
        assert response.json() == OAUTH_FAILED

    async def test_email_of_existing_account_requires_explicit_linking(
        self, auth_client: AsyncClient, idp: FakeOidcProvider, db_session: AsyncSession
    ) -> None:
        await registered_tokens(auth_client, email="gina@example.com")
        users = (await db_session.execute(select(func.count()).select_from(User))).scalar_one()

        response = await complete(auth_client, idp)

        assert response.status_code == 409
        assert response.json() == LINK_REQUIRED
        after = (await db_session.execute(select(func.count()).select_from(User))).scalar_one()
        assert after == users

    async def test_inactive_user_is_a_generic_401(
        self, auth_client: AsyncClient, idp: FakeOidcProvider, db_session: AsyncSession
    ) -> None:
        body = (await complete(auth_client, idp)).json()
        user = await db_session.get(User, uuid.UUID(body["user"]["id"]))
        assert user is not None
        user.is_active = False
        await db_session.flush()

        response = await complete(auth_client, idp)

        assert response.status_code == 401
        assert response.json() == OAUTH_FAILED

    async def test_errors_leak_nothing(
        self, auth_client: AsyncClient, idp: FakeOidcProvider
    ) -> None:
        started = await start(auth_client, idp)
        code, state = idp.authorize(started["authorization_url"])
        idp.token_response = lambda: httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "Bad code " + code}
        )

        response = await auth_client.post(
            callback_url(name_of(idp)),
            json={"code": code, "state": state, "attempt_token": started["attempt_token"]},
        )

        for leaked in (
            code,
            state,
            started["attempt_token"],
            "invalid_grant",
            *idp.sensitive_values(),
        ):
            assert leaked not in response.text


class TestCrossProvider:
    async def test_state_from_one_provider_fails_at_the_other(
        self, auth_client: AsyncClient, auth_app: FastAPI
    ) -> None:
        clock = FrozenClock(datetime.now(UTC).replace(microsecond=0))
        auth_app.state.clock = clock
        google, apple = FakeGoogle(clock=clock), FakeApple(clock=clock)
        auth_app.state.google_oauth = google.client()
        auth_app.state.apple_oauth = apple.client()
        started = await start(auth_client, google)
        code, state = google.authorize(started["authorization_url"])

        response = await auth_client.post(
            callback_url("apple"),
            json={"code": code, "state": state, "attempt_token": started["attempt_token"]},
        )

        assert response.status_code == 401
        assert apple.token_requests == []


class TestNotConfigured:
    @pytest.mark.parametrize("name", PROVIDERS)
    @pytest.mark.parametrize("url", [start_url, callback_url])
    async def test_endpoints_are_absent_without_configuration(
        self, auth_client: AsyncClient, auth_app: FastAPI, name: str, url: Any
    ) -> None:
        setattr(auth_app.state, f"{name}_oauth", None)

        response = await auth_client.post(
            url(name), json={"code": "c", "state": "s", "attempt_token": "t"}
        )

        assert response.status_code == 404
        assert response.json() == {"error": {"code": "not_found", "message": "Not found"}}


class TestRateLimiting:
    @pytest.fixture
    async def limited(self, auth_app: FastAPI, idp: FakeOidcProvider) -> AsyncIterator[AsyncClient]:
        auth_app.state.rate_limits = DEFAULT_AUTH_RATE_LIMITS
        transport = ASGITransport(
            app=auth_app, raise_app_exceptions=False, client=("203.0.113.30", 40000)
        )
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client

    async def test_start_per_ip(self, limited: AsyncClient, idp: FakeOidcProvider) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.oauth_start_per_ip.limit

        statuses = [
            (await limited.post(start_url(name_of(idp)))).status_code for _ in range(limit + 1)
        ]

        assert statuses[:limit] == [200] * limit
        assert statuses[limit] == 429

    async def test_callback_per_ip(self, limited: AsyncClient, idp: FakeOidcProvider) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.oauth_callback_per_ip.limit
        payload = {"code": "c", "state": "s", "attempt_token": "t"}

        statuses = [
            (await limited.post(callback_url(name_of(idp)), json=payload)).status_code
            for _ in range(limit + 1)
        ]

        assert statuses[:limit] == [401] * limit
        assert statuses[limit] == 429

    async def test_providers_share_one_per_ip_budget(
        self, limited: AsyncClient, auth_app: FastAPI, idp: FakeOidcProvider
    ) -> None:
        """Both protect the same resources (attempt rows, callback work): one budget per IP."""
        clock = auth_app.state.clock
        auth_app.state.google_oauth = FakeGoogle(clock=clock).client()
        auth_app.state.apple_oauth = FakeApple(clock=clock).client()
        limit = DEFAULT_AUTH_RATE_LIMITS.oauth_start_per_ip.limit
        for i in range(limit):
            await limited.post(start_url(PROVIDERS[i % 2]))

        assert (await limited.post(start_url("google"))).status_code == 429
        assert (await limited.post(start_url("apple"))).status_code == 429


class TestLogging:
    async def test_full_flow_logs_no_secrets(
        self,
        auth_client: AsyncClient,
        idp: FakeOidcProvider,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        started = await start(auth_client, idp)
        query = dict(
            part.split("=", 1) for part in started["authorization_url"].split("?", 1)[1].split("&")
        )
        code, state = idp.authorize(started["authorization_url"])
        payload = {"code": code, "state": state, "attempt_token": started["attempt_token"]}
        body = (await auth_client.post(callback_url(name_of(idp)), json=payload)).json()
        await auth_client.post(callback_url(name_of(idp)), json=payload)

        logged = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
        for secret in (
            code,
            state,
            query["nonce"],
            query["code_challenge"],
            started["attempt_token"],
            body["access_token"],
            body["refresh_token"],
            idp.subject,
            "gina@example.com",
            "eyJ",
            *idp.sensitive_values(),
        ):
            assert secret not in logged
        assert f"user_id={body['user']['id']}" in logged


GOOGLE_SETTINGS = {
    "google_client_id": "1234-abc.apps.googleusercontent.com",
    "google_client_secret": "GOCSPX-test-secret-value-Zr8",
    "google_redirect_uri": "https://app.example.com/oauth/google/callback",
}


def apple_settings() -> dict[str, str]:
    return {
        "apple_team_id": "ABCDE12345",
        "apple_key_id": "KEY0123456",
        "apple_client_id": "com.example.homeinventory.signin",
        "apple_private_key": team_key_pem(),
        "apple_redirect_uri": "https://app.example.com/oauth/apple/callback",
    }


class TestWiring:
    @pytest.mark.parametrize(
        ("name", "settings", "client_type"),
        [
            ("google", lambda: GOOGLE_SETTINGS, GoogleOAuthClient),
            ("apple", apple_settings, AppleOAuthClient),
        ],
    )
    async def test_configured_app_creates_and_closes_the_provider_client(
        self,
        app_with_settings: Any,
        name: str,
        settings: Any,
        client_type: type[GoogleOAuthClient | AppleOAuthClient],
    ) -> None:
        app = app_with_settings(**settings())
        client = getattr(app.state, f"{name}_oauth")
        assert isinstance(client, client_type)
        http: httpx.AsyncClient = client._http

        async with app.router.lifespan_context(app):
            assert not http.is_closed

        assert http.is_closed

    @pytest.mark.parametrize("name", PROVIDERS)
    async def test_unconfigured_app_has_no_provider_client(self, app: FastAPI, name: str) -> None:
        assert getattr(app.state, f"{name}_oauth") is None


async def test_app_startup_with_apple_configured_never_logs_the_key(
    app_with_settings: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)

    app = app_with_settings(**apple_settings())
    async with app.router.lifespan_context(app):
        pass

    body = "".join(team_key_pem().splitlines()[1:-1])
    assert body[:40] not in caplog.text
    assert "PRIVATE KEY" not in caplog.text
