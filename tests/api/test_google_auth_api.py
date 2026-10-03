"""POST /auth/google/start and POST /auth/google/callback (Step 8)."""

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
from app.services.google_oauth import GoogleOAuthClient
from tests.support.auth import API, bearer, registered_tokens
from tests.support.clock import FrozenClock
from tests.support.google import CLIENT_SECRET, FakeGoogle

START = f"{API}/google/start"
CALLBACK = f"{API}/google/callback"
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


@pytest.fixture
def google(auth_app: FastAPI) -> FakeGoogle:
    # Real-time-ish frozen clock shared by the app and the fake provider.
    clock = FrozenClock(datetime.now(UTC).replace(microsecond=0))
    auth_app.state.clock = clock
    fake = FakeGoogle(clock=clock)
    auth_app.state.google_oauth = fake.client()
    return fake


async def start(client: AsyncClient) -> dict[str, Any]:
    response = await client.post(START)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def complete(client: AsyncClient, google: FakeGoogle) -> httpx.Response:
    started = await start(client)
    code, state = google.authorize(started["authorization_url"])
    return await client.post(
        CALLBACK, json={"code": code, "state": state, "attempt_token": started["attempt_token"]}
    )


class TestStart:
    async def test_returns_authorization_url_and_binding_token(
        self, auth_client: AsyncClient, google: FakeGoogle
    ) -> None:
        response = await auth_client.post(START)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"authorization_url", "attempt_token", "expires_in"}
        assert body["authorization_url"].startswith("https://accounts.google.com/")
        assert body["attempt_token"] not in body["authorization_url"]
        assert body["expires_in"] == 600
        assert response.headers["cache-control"] == "no-store"

    async def test_get_is_not_allowed(self, auth_client: AsyncClient, google: FakeGoogle) -> None:
        assert (await auth_client.get(START)).status_code == 405
        assert (await auth_client.get(CALLBACK)).status_code == 405


class TestCallback:
    async def test_new_google_user_gets_the_standard_auth_response(
        self, auth_client: AsyncClient, google: FakeGoogle
    ) -> None:
        response = await complete(auth_client, google)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"access_token", "refresh_token", "token_type", "expires_in", "user"}
        assert body["user"]["auth_provider"] == "google"
        assert body["user"]["email"] == "gina@example.com"
        assert body["user"]["is_active"] is True

    async def test_tokens_work_with_existing_session_endpoints(
        self, auth_client: AsyncClient, google: FakeGoogle
    ) -> None:
        body = (await complete(auth_client, google)).json()

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
        self, auth_client: AsyncClient, google: FakeGoogle
    ) -> None:
        first = (await complete(auth_client, google)).json()
        second = (await complete(auth_client, google)).json()

        assert second["user"]["id"] == first["user"]["id"]

    @pytest.mark.parametrize(
        "extra",
        [{"sub": "attacker"}, {"email": "victim@example.com"}, {"id_token": "eyJ.x.y"}],
    )
    async def test_client_supplied_identity_is_refused(
        self, auth_client: AsyncClient, google: FakeGoogle, extra: dict[str, str]
    ) -> None:
        started = await start(auth_client)
        code, state = google.authorize(started["authorization_url"])

        response = await auth_client.post(
            CALLBACK,
            json={"code": code, "state": state, "attempt_token": started["attempt_token"], **extra},
        )

        assert response.status_code == 422
        assert google.token_requests == []

    @pytest.mark.parametrize("missing", ["code", "state", "attempt_token"])
    async def test_all_fields_are_required(
        self, auth_client: AsyncClient, google: FakeGoogle, missing: str
    ) -> None:
        body = {"code": "c", "state": "s", "attempt_token": "t"}
        del body[missing]

        assert (await auth_client.post(CALLBACK, json=body)).status_code == 422

    async def test_replayed_callback_is_rejected(
        self, auth_client: AsyncClient, google: FakeGoogle
    ) -> None:
        started = await start(auth_client)
        code, state = google.authorize(started["authorization_url"])
        payload = {"code": code, "state": state, "attempt_token": started["attempt_token"]}
        first = await auth_client.post(CALLBACK, json=payload)

        replay = await auth_client.post(CALLBACK, json=payload)

        assert first.status_code == 200
        assert replay.status_code == 401
        assert replay.json() == OAUTH_FAILED

    async def test_unknown_state_is_a_generic_401(
        self, auth_client: AsyncClient, google: FakeGoogle
    ) -> None:
        response = await auth_client.post(
            CALLBACK, json={"code": "c", "state": "forged", "attempt_token": "t"}
        )

        assert response.status_code == 401
        assert response.json() == OAUTH_FAILED

    async def test_provider_outage_is_a_generic_503(
        self, auth_client: AsyncClient, google: FakeGoogle
    ) -> None:
        google.token_response = lambda: httpx.Response(
            500, json={"error": "backendError", "detail": "google-internal-detail"}
        )

        response = await complete(auth_client, google)

        assert response.status_code == 503
        assert response.json() == UNAVAILABLE
        assert "google-internal-detail" not in response.text

    async def test_invalid_id_token_is_a_generic_401(
        self, auth_client: AsyncClient, google: FakeGoogle
    ) -> None:
        google.claim_overrides = {"aud": "someone-else"}

        response = await complete(auth_client, google)

        assert response.status_code == 401
        assert response.json() == OAUTH_FAILED

    async def test_email_of_existing_account_requires_explicit_linking(
        self, auth_client: AsyncClient, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        await registered_tokens(auth_client, email="gina@example.com")
        users = (await db_session.execute(select(func.count()).select_from(User))).scalar_one()

        response = await complete(auth_client, google)

        assert response.status_code == 409
        assert response.json() == LINK_REQUIRED
        after = (await db_session.execute(select(func.count()).select_from(User))).scalar_one()
        assert after == users

    async def test_inactive_user_is_a_generic_401(
        self, auth_client: AsyncClient, google: FakeGoogle, db_session: AsyncSession
    ) -> None:
        body = (await complete(auth_client, google)).json()
        user = await db_session.get(User, uuid.UUID(body["user"]["id"]))
        assert user is not None
        user.is_active = False
        await db_session.flush()

        response = await complete(auth_client, google)

        assert response.status_code == 401
        assert response.json() == OAUTH_FAILED

    async def test_errors_leak_nothing(self, auth_client: AsyncClient, google: FakeGoogle) -> None:
        started = await start(auth_client)
        code, state = google.authorize(started["authorization_url"])
        google.token_response = lambda: httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "Bad code " + code}
        )

        response = await auth_client.post(
            CALLBACK, json={"code": code, "state": state, "attempt_token": started["attempt_token"]}
        )

        for leaked in (code, state, started["attempt_token"], CLIENT_SECRET, "invalid_grant"):
            assert leaked not in response.text


class TestNotConfigured:
    @pytest.mark.parametrize("path", [START, CALLBACK])
    async def test_endpoints_are_absent_without_google_configuration(
        self, auth_client: AsyncClient, auth_app: FastAPI, path: str
    ) -> None:
        auth_app.state.google_oauth = None

        response = await auth_client.post(
            path, json={"code": "c", "state": "s", "attempt_token": "t"}
        )

        assert response.status_code == 404
        assert response.json() == {"error": {"code": "not_found", "message": "Not found"}}


class TestRateLimiting:
    @pytest.fixture
    async def limited(self, auth_app: FastAPI, google: FakeGoogle) -> AsyncIterator[AsyncClient]:
        auth_app.state.rate_limits = DEFAULT_AUTH_RATE_LIMITS
        transport = ASGITransport(
            app=auth_app, raise_app_exceptions=False, client=("203.0.113.30", 40000)
        )
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client

    async def test_start_per_ip(self, limited: AsyncClient) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.oauth_start_per_ip.limit

        statuses = [(await limited.post(START)).status_code for _ in range(limit + 1)]

        assert statuses[:limit] == [200] * limit
        assert statuses[limit] == 429

    async def test_callback_per_ip(self, limited: AsyncClient) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.oauth_callback_per_ip.limit
        payload = {"code": "c", "state": "s", "attempt_token": "t"}

        statuses = [
            (await limited.post(CALLBACK, json=payload)).status_code for _ in range(limit + 1)
        ]

        assert statuses[:limit] == [401] * limit
        assert statuses[limit] == 429


class TestLogging:
    async def test_full_flow_logs_no_secrets(
        self, auth_client: AsyncClient, google: FakeGoogle, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        started = await start(auth_client)
        code, state = google.authorize(started["authorization_url"])
        payload = {"code": code, "state": state, "attempt_token": started["attempt_token"]}
        body = (await auth_client.post(CALLBACK, json=payload)).json()
        await auth_client.post(CALLBACK, json=payload)

        logged = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
        for secret in (
            code,
            state,
            started["attempt_token"],
            body["access_token"],
            body["refresh_token"],
            CLIENT_SECRET,
            google.subject,
            "ya29.",
        ):
            assert secret not in logged


class TestWiring:
    async def test_configured_app_creates_and_closes_a_google_client(
        self, app_with_settings: Any
    ) -> None:
        app = app_with_settings(
            google_client_id="1234-abc.apps.googleusercontent.com",
            google_client_secret="GOCSPX-test-secret-value-Zr8",
            google_redirect_uri="https://app.example.com/oauth/google/callback",
        )
        client = app.state.google_oauth
        assert isinstance(client, GoogleOAuthClient)

        async with app.router.lifespan_context(app):
            assert not client._http.is_closed

        assert client._http.is_closed

    async def test_unconfigured_app_has_no_google_client(self, app: FastAPI) -> None:
        assert app.state.google_oauth is None
