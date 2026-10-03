"""Step 7: production HTTPS enforcement, trusted-proxy handling and Host validation.

Deployment model under test (ARCHITECTURE.md §5, Transport): TLS ends at the load balancer;
uvicorn runs with --proxy-headers --forwarded-allow-ips=<LB range>, so only the LB may set the
scheme via X-Forwarded-Proto. Tests reproduce that by wrapping the app in uvicorn's own
ProxyHeadersMiddleware; the app itself must never read forwarded headers.
"""

from collections.abc import AsyncIterator
from typing import Any, cast

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.types import ASGIApp
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.core.database import get_db_session
from app.main import create_app
from app.models.user import User
from tests.conftest import GENEROUS_RATE_LIMITS, AppFactory, dispose_app, load_test_settings
from tests.support.auth import API
from tests.support.passwords import STRONG_PASSWORD, fast_hasher

PROD_HOST = "api.example.com"
HTTPS_URL = f"https://{PROD_HOST}"
HTTP_URL = f"http://{PROD_HOST}"
CLIENT_IP = "203.0.113.7"
LB_IP = "10.0.0.2"  # the only peer allowed to set X-Forwarded-* (--forwarded-allow-ips)

HTTPS_REQUIRED = {"error": {"code": "https_required", "message": "HTTPS is required"}}
INVALID_HOST = {"error": {"code": "invalid_host", "message": "Invalid host"}}
PROBES = ["/health", "/health/ready"]


def client_for(app: ASGIApp, base_url: str = HTTPS_URL, peer: str = CLIENT_IP) -> AsyncClient:
    transport = ASGITransport(app=app, raise_app_exceptions=False, client=(peer, 40000))
    return AsyncClient(transport=transport, base_url=base_url)


def behind_load_balancer(app: FastAPI) -> ASGIApp:
    """What `uvicorn --proxy-headers --forwarded-allow-ips=10.0.0.2` puts in front of the app."""
    # uvicorn and Starlette type the same ASGI interface differently.
    return cast(ASGIApp, ProxyHeadersMiddleware(cast(Any, app), trusted_hosts=LB_IP))


async def users_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(User))).scalar_one()


@pytest.fixture
async def prod_app(test_settings: Any, db_session: AsyncSession) -> AsyncIterator[FastAPI]:
    """Production settings, wired to the per-test rollback session like `auth_app`."""

    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db_session

    app = create_app(load_test_settings(environment="production", allowed_hosts=[PROD_HOST]))
    app.dependency_overrides[get_db_session] = override_db
    app.state.password_hasher = fast_hasher()
    app.state.rate_limits = GENEROUS_RATE_LIMITS
    yield app
    await dispose_app(app)


def assert_rejected(response: Response, body: dict[str, Any]) -> None:
    assert response.status_code == 400
    assert response.json() == body
    assert "location" not in response.headers  # rejected, never redirected (no loops)
    # Rejections still carry the security headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["strict-transport-security"].startswith("max-age=")


class TestHttpsEnforcement:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", f"{API}/me"),
            ("POST", f"{API}/guest"),
            ("POST", f"{API}/login"),
            ("GET", "/docs"),
            ("GET", "/does-not-exist"),
            ("OPTIONS", f"{API}/login"),
        ],
    )
    async def test_production_rejects_plain_http(
        self, prod_app: FastAPI, method: str, path: str
    ) -> None:
        async with client_for(prod_app, HTTP_URL) as client:
            response = await client.request(method, path)

        assert_rejected(response, HTTPS_REQUIRED)

    async def test_rejected_request_never_reaches_the_application(
        self, prod_app: FastAPI, db_session: AsyncSession
    ) -> None:
        before = await users_count(db_session)
        async with client_for(prod_app, HTTP_URL) as client:
            response = await client.post(f"{API}/guest")

        assert response.status_code == 400
        assert await users_count(db_session) == before

    async def test_production_accepts_https(self, prod_app: FastAPI) -> None:
        async with client_for(prod_app) as client:
            response = await client.post(f"{API}/guest")

        assert response.status_code == 201

    @pytest.mark.parametrize("environment", ["local", "test"])
    async def test_non_production_works_over_http(
        self, app_with_settings: AppFactory, environment: str
    ) -> None:
        async with client_for(app_with_settings(environment=environment), "http://test") as c:
            me = await c.get(f"{API}/me")
            health = await c.get("/health")

        assert me.status_code == 401  # reached the app: authentication, not transport, failed
        assert health.status_code == 200

    @pytest.mark.parametrize("path", PROBES)
    async def test_probes_are_reachable_over_http(self, prod_app: FastAPI, path: str) -> None:
        async with client_for(prod_app, HTTP_URL) as client:
            response = await client.get(path)

        assert response.status_code == 200

    @pytest.mark.parametrize(
        "path",
        ["/health/", "/healthz", "/health/ready/x", "/HEALTH", "/health/../api/v1/auth/me"],
    )
    async def test_only_the_exact_probe_paths_are_exempt(
        self, prod_app: FastAPI, path: str
    ) -> None:
        async with client_for(prod_app, HTTP_URL) as client:
            response = await client.get(path)

        assert_rejected(response, HTTPS_REQUIRED)

    async def test_rejection_leaks_no_configuration(self, prod_app: FastAPI) -> None:
        settings = prod_app.state.settings
        async with client_for(prod_app, HTTP_URL) as client:
            response = await client.get(f"{API}/me", headers={"authorization": "Bearer abc.def"})

        raw = response.text + str(dict(response.headers))
        for leaked in (
            PROD_HOST,
            settings.jwt_secret.get_secret_value(),
            settings.database_url.get_secret_value(),
            "abc.def",
            "http://",
            "scheme",
            "forwarded",
            "uvicorn",
        ):
            assert leaked not in raw


class TestForwardedHeaders:
    @pytest.mark.parametrize(
        "headers",
        [
            {"x-forwarded-proto": "https"},
            {"forwarded": "proto=https"},
            {"x-forwarded-scheme": "https"},
            {"x-forwarded-ssl": "on"},
            {"x-url-scheme": "https"},
            {"front-end-https": "on"},
        ],
    )
    async def test_app_itself_never_trusts_forwarded_headers(
        self, prod_app: FastAPI, headers: dict[str, str]
    ) -> None:
        async with client_for(prod_app, HTTP_URL) as client:
            response = await client.get(f"{API}/me", headers=headers)

        assert_rejected(response, HTTPS_REQUIRED)

    async def test_load_balancer_can_mark_the_request_as_https(self, prod_app: FastAPI) -> None:
        async with client_for(behind_load_balancer(prod_app), HTTP_URL, peer=LB_IP) as client:
            response = await client.post(f"{API}/guest", headers={"x-forwarded-proto": "https"})

        assert response.status_code == 201

    async def test_untrusted_peer_cannot_claim_https(self, prod_app: FastAPI) -> None:
        async with client_for(behind_load_balancer(prod_app), HTTP_URL, peer=CLIENT_IP) as client:
            response = await client.post(f"{API}/guest", headers={"x-forwarded-proto": "https"})

        assert_rejected(response, HTTPS_REQUIRED)

    @pytest.mark.parametrize("proto", ["http", "HTTPS", "https,http", "javascript:", "", "wss"])
    async def test_load_balancer_reporting_anything_but_https_is_rejected(
        self, prod_app: FastAPI, proto: str
    ) -> None:
        async with client_for(behind_load_balancer(prod_app), HTTP_URL, peer=LB_IP) as client:
            response = await client.get(f"{API}/me", headers={"x-forwarded-proto": proto})

        assert_rejected(response, HTTPS_REQUIRED)

    async def test_load_balancer_without_proto_header_is_rejected(self, prod_app: FastAPI) -> None:
        async with client_for(behind_load_balancer(prod_app), HTTP_URL, peer=LB_IP) as client:
            response = await client.get(f"{API}/me")

        assert_rejected(response, HTTPS_REQUIRED)

    async def test_host_is_still_validated_behind_the_load_balancer(
        self, prod_app: FastAPI
    ) -> None:
        async with client_for(behind_load_balancer(prod_app), HTTP_URL, peer=LB_IP) as client:
            response = await client.get(
                f"{API}/me", headers={"x-forwarded-proto": "https", "host": "evil.example"}
            )

        assert_rejected(response, INVALID_HOST)


class TestTrustedHost:
    async def test_configured_host_is_accepted(self, prod_app: FastAPI) -> None:
        async with client_for(prod_app) as client:
            response = await client.post(f"{API}/guest")

        assert response.status_code == 201

    @pytest.mark.parametrize(
        "host",
        [
            "evil.example",
            "evil.api.example.com",
            "api.example.com.evil.example",
            "localhost",
            "10.0.0.5",
            "api.example.com@evil.example",
            "api.example.com/x",
            "",
        ],
    )
    async def test_unapproved_host_is_rejected(self, prod_app: FastAPI, host: str) -> None:
        async with client_for(prod_app) as client:
            response = await client.get(f"{API}/me", headers={"host": host})

        assert_rejected(response, INVALID_HOST)
        if host:
            assert host not in response.text
        assert PROD_HOST not in response.text

    async def test_rejected_host_never_reaches_the_application(
        self, prod_app: FastAPI, db_session: AsyncSession
    ) -> None:
        before = await users_count(db_session)
        async with client_for(prod_app) as client:
            response = await client.post(f"{API}/guest", headers={"host": "evil.example"})

        assert response.status_code == 400
        assert await users_count(db_session) == before

    async def test_port_is_not_part_of_the_match(self, prod_app: FastAPI) -> None:
        """Documented: hosts match by name; the LB decides which ports are exposed at all."""
        async with client_for(prod_app) as client:
            response = await client.post(f"{API}/guest", headers={"host": f"{PROD_HOST}:8443"})

        assert response.status_code == 201

    async def test_x_forwarded_host_is_ignored(self, prod_app: FastAPI) -> None:
        async with client_for(prod_app) as client:
            spoofed = await client.get(
                f"{API}/me", headers={"host": "evil.example", "x-forwarded-host": PROD_HOST}
            )
            ignored = await client.get(f"{API}/me", headers={"x-forwarded-host": "evil.example"})

        assert_rejected(spoofed, INVALID_HOST)
        assert ignored.status_code == 401

    @pytest.mark.parametrize("path", PROBES)
    async def test_probes_are_reachable_by_instance_address(
        self, prod_app: FastAPI, path: str
    ) -> None:
        """Health checks address the instance directly (Host: <ip>:<port>), usually over HTTP."""
        async with client_for(prod_app, "http://10.0.0.5:8000", peer=LB_IP) as client:
            response = await client.get(path)

        assert response.status_code == 200

    async def test_local_explicit_host_configuration_is_enforced(
        self, app_with_settings: AppFactory
    ) -> None:
        app = app_with_settings(environment="local", allowed_hosts=["localhost"])
        async with client_for(app, "http://localhost:8000") as client:
            allowed = await client.get(f"{API}/me")
            other = await client.get(f"{API}/me", headers={"host": "evil.example"})

        assert allowed.status_code == 401
        assert other.status_code == 400
        assert other.json() == INVALID_HOST

    async def test_local_without_configuration_accepts_any_host(
        self, app_with_settings: AppFactory
    ) -> None:
        async with client_for(app_with_settings(environment="local"), "http://192.168.1.20") as c:
            response = await c.get(f"{API}/me")

        assert response.status_code == 401


class TestProductionRegression:
    async def test_security_headers_remain(self, prod_app: FastAPI) -> None:
        async with client_for(prod_app) as client:
            response = await client.get("/health")

        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert response.headers["strict-transport-security"].startswith("max-age=")

    @pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
    async def test_docs_stay_hidden(self, prod_app: FastAPI, path: str) -> None:
        async with client_for(prod_app) as client:
            assert (await client.get(path)).status_code == 404

    async def test_readiness_reports_ok(self, prod_app: FastAPI) -> None:
        async with client_for(prod_app) as client:
            response = await client.get("/health/ready")

        assert response.json() == {"status": "ok", "database": "ok"}

    async def test_full_auth_flow_over_https(self, prod_app: FastAPI) -> None:
        credentials = {"email": "alice@example.com", "password": STRONG_PASSWORD}
        async with client_for(prod_app) as client:
            registered = await client.post(f"{API}/register", json=credentials)
            logged_in = await client.post(f"{API}/login", json=credentials)
            tokens = logged_in.json()
            refreshed = await client.post(
                f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}
            )
            access = refreshed.json()["access_token"]
            me = await client.get(f"{API}/me", headers={"authorization": f"Bearer {access}"})
            out = await client.post(
                f"{API}/logout-all", headers={"authorization": f"Bearer {access}"}
            )
            after = await client.get(f"{API}/me", headers={"authorization": f"Bearer {access}"})

        assert [r.status_code for r in (registered, logged_in, refreshed, me, out, after)] == [
            201,
            200,
            200,
            200,
            204,
            401,
        ]

    async def test_cors_preflight_still_works(
        self, test_settings: Any, db_session: AsyncSession
    ) -> None:
        origin = "https://app.example.com"
        app = create_app(
            load_test_settings(
                environment="production", allowed_hosts=[PROD_HOST], cors_origins=[origin]
            )
        )
        try:
            async with client_for(app) as client:
                allowed = await client.options(
                    f"{API}/login",
                    headers={"origin": origin, "access-control-request-method": "POST"},
                )
                denied = await client.options(
                    f"{API}/login",
                    headers={
                        "origin": "https://evil.example",
                        "access-control-request-method": "POST",
                    },
                )
        finally:
            await dispose_app(app)

        assert allowed.status_code == 200
        assert allowed.headers["access-control-allow-origin"] == origin
        assert "access-control-allow-credentials" not in allowed.headers
        assert allowed.headers["strict-transport-security"].startswith("max-age=")
        assert denied.headers.get("access-control-allow-origin") not in (
            "*",
            "https://evil.example",
        )
