import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from pydantic import BaseModel, Field

from tests.conftest import AppFactory, make_client

EXPECTED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}


class _CredentialsBody(BaseModel):
    email: str = Field(max_length=10)
    password: str = Field(min_length=12)


def _add_probe_routes(app: FastAPI) -> None:
    async def boom() -> None:
        raise RuntimeError("database password is hunter2 at 10.0.0.5")

    async def echo(body: _CredentialsBody) -> dict[str, str]:
        return {"ok": "yes"}

    app.add_api_route("/_probe/boom", boom, methods=["GET"])
    app.add_api_route("/_probe/echo", echo, methods=["POST"])


@pytest.fixture
async def probe_client(app: FastAPI) -> AsyncClient:
    _add_probe_routes(app)
    return make_client(app)


class TestSecurityHeaders:
    async def test_present_on_success(self, client: AsyncClient) -> None:
        response = await client.get("/health")

        for header, value in EXPECTED_SECURITY_HEADERS.items():
            assert response.headers.get(header) == value
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

    async def test_present_on_not_found(self, client: AsyncClient) -> None:
        response = await client.get("/does-not-exist")

        assert response.headers.get("x-content-type-options") == "nosniff"

    async def test_present_on_internal_error(self, probe_client: AsyncClient) -> None:
        async with probe_client as c:
            response = await c.get("/_probe/boom")

        for header, value in EXPECTED_SECURITY_HEADERS.items():
            assert response.headers.get(header) == value

    async def test_no_hsts_outside_production(self, client: AsyncClient) -> None:
        response = await client.get("/health")

        assert "strict-transport-security" not in response.headers

    async def test_hsts_in_production(self, app_with_settings: AppFactory) -> None:
        async with make_client(app_with_settings(environment="production")) as c:
            response = await c.get("/health")

        assert response.headers["strict-transport-security"].startswith("max-age=")


class TestSafeErrors:
    async def test_not_found_uses_safe_envelope(self, client: AsyncClient) -> None:
        response = await client.get("/does-not-exist")

        assert response.status_code == 404
        assert response.json() == {"error": {"code": "not_found", "message": "Not found"}}

    async def test_unhandled_exception_hides_details(self, probe_client: AsyncClient) -> None:
        async with probe_client as c:
            response = await c.get("/_probe/boom")

        assert response.status_code == 500
        assert response.json() == {
            "error": {"code": "internal_error", "message": "Internal server error"}
        }
        for leaked in ("hunter2", "10.0.0.5", "RuntimeError", "Traceback"):
            assert leaked not in response.text

    async def test_validation_error_does_not_echo_input(self, probe_client: AsyncClient) -> None:
        secret_password = "short-pw"
        async with probe_client as c:
            response = await c.post(
                "/_probe/echo",
                json={"email": "far-too-long@example.com", "password": secret_password},
            )

        assert response.status_code == 422
        body = response.json()
        assert body["error"]["code"] == "validation_error"
        assert {tuple(d["loc"]) for d in body["error"]["details"]} == {
            ("body", "email"),
            ("body", "password"),
        }
        assert secret_password not in response.text
        assert "far-too-long@example.com" not in response.text

    async def test_malformed_json_is_rejected_safely(self, probe_client: AsyncClient) -> None:
        async with probe_client as c:
            response = await c.post(
                "/_probe/echo",
                content=b'{"password": "leak-me-please"',
                headers={"content-type": "application/json"},
            )

        assert response.status_code == 422
        assert "leak-me-please" not in response.text


class TestApiDocsExposure:
    @pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
    async def test_docs_available_outside_production(self, client: AsyncClient, path: str) -> None:
        assert (await client.get(path)).status_code == 200

    @pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
    async def test_docs_hidden_in_production(
        self, app_with_settings: AppFactory, path: str
    ) -> None:
        async with make_client(app_with_settings(environment="production")) as c:
            response = await c.get(path)

        assert response.status_code == 404


class TestCors:
    ALLOWED = "https://app.example.com"

    async def _preflight(self, app: FastAPI, origin: str) -> dict[str, str]:
        async with make_client(app) as c:
            response = await c.options(
                "/health",
                headers={"origin": origin, "access-control-request-method": "GET"},
            )
        return dict(response.headers)

    async def test_no_cors_headers_by_default(self, app: FastAPI) -> None:
        headers = await self._preflight(app, "https://evil.example")

        assert "access-control-allow-origin" not in headers

    async def test_allowed_origin_is_echoed_exactly(self, app_with_settings: AppFactory) -> None:
        app = app_with_settings(cors_origins=[self.ALLOWED])

        headers = await self._preflight(app, self.ALLOWED)

        assert headers["access-control-allow-origin"] == self.ALLOWED

    async def test_unlisted_origin_is_not_allowed(self, app_with_settings: AppFactory) -> None:
        app = app_with_settings(cors_origins=[self.ALLOWED])

        headers = await self._preflight(app, "https://evil.example")

        assert headers.get("access-control-allow-origin") not in ("*", "https://evil.example")

    async def test_credentials_not_allowed(self, app_with_settings: AppFactory) -> None:
        # Mobile clients send bearer tokens in headers; cookies are never needed.
        app = app_with_settings(cors_origins=[self.ALLOWED])

        headers = await self._preflight(app, self.ALLOWED)

        assert "access-control-allow-credentials" not in headers
