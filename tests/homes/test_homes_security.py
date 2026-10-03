"""Homes authorization, IDOR, rate limiting, logging and production transport behaviour."""

import logging
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.rate_limit import DEFAULT_RESOURCE_RATE_LIMITS
from app.main import create_app
from app.models.user import User
from app.repositories.home_repository import HomeRepository
from tests.conftest import (
    GENEROUS_RATE_LIMITS,
    GENEROUS_RESOURCE_RATE_LIMITS,
    dispose_app,
    load_test_settings,
)
from tests.support.auth import API, login, register
from tests.support.homes import HOMES, create_home, created_home, owner
from tests.support.passwords import fast_hasher

NOT_FOUND = {"error": {"code": "not_found", "message": "Not found"}}
UNAUTHORIZED = {"error": {"code": "unauthorized", "message": "Authentication required"}}


def endpoints(home_id: str) -> list[tuple[str, str, dict[str, Any] | None]]:
    return [
        ("POST", HOMES, {"name": "X", "currency": "USD"}),
        ("GET", HOMES, None),
        ("GET", f"{HOMES}/{home_id}", None),
        ("PATCH", f"{HOMES}/{home_id}", {"name": "Y"}),
        ("DELETE", f"{HOMES}/{home_id}", None),
    ]


async def call(
    client: AsyncClient, method: str, url: str, body: Any, headers: dict[str, str] | None
) -> Any:
    return await client.request(method, url, json=body, headers=headers)


class TestAuthentication:
    @pytest.mark.parametrize("index", range(5))
    async def test_no_token_is_401(self, auth_client: AsyncClient, index: int) -> None:
        method, url, body = endpoints(str(uuid.uuid7()))[index]

        response = await call(auth_client, method, url, body, None)

        assert response.status_code == 401
        assert response.json() == UNAUTHORIZED

    @pytest.mark.parametrize("state", ["revoked_session", "inactive_user", "deleted_user"])
    @pytest.mark.parametrize("index", range(5))
    async def test_dead_principals_are_401(
        self, auth_client: AsyncClient, db_session: AsyncSession, state: str, index: int
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        home = await created_home(auth_client, alice)
        user_id = uuid.UUID(alice["id"])
        if state == "revoked_session":
            await auth_client.post(f"{API}/logout", headers=alice["headers"])
        elif state == "inactive_user":
            await db_session.execute(update(User).where(User.id == user_id).values(is_active=False))
        else:
            await db_session.execute(delete(User).where(User.id == user_id))
        method, url, body = endpoints(home["id"])[index]

        response = await call(auth_client, method, url, body, alice["headers"])

        assert response.status_code == 401
        assert response.json() == UNAUTHORIZED


class TestIdor:
    async def test_other_users_home_is_indistinguishable_from_a_missing_one(
        self, auth_client: AsyncClient
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        mallory = await owner(auth_client, "mallory@example.com")
        home = await created_home(auth_client, alice, name="Main", currency="USD")
        url, missing = f"{HOMES}/{home['id']}", f"{HOMES}/{uuid.uuid7()}"

        for method, body in (("GET", None), ("PATCH", {"name": "Pwned"}), ("DELETE", None)):
            theirs = await call(auth_client, method, url, body, mallory["headers"])
            nothing = await call(auth_client, method, missing, body, mallory["headers"])
            assert (theirs.status_code, theirs.json()) == (404, NOT_FOUND)
            assert (nothing.status_code, nothing.content) == (404, theirs.content)

        after = (await auth_client.get(url, headers=alice["headers"])).json()
        assert after == home

    async def test_lists_never_mix_owners(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        mallory = await owner(auth_client)
        await created_home(auth_client, alice, name="Alice's")

        listed = await auth_client.get(
            HOMES, params={"user_id": alice["id"]}, headers=mallory["headers"]
        )

        assert listed.json() == {"items": []}

    async def test_forged_user_id_cannot_create_for_someone_else(
        self, auth_client: AsyncClient
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        mallory = await owner(auth_client)

        forged = await auth_client.post(
            HOMES,
            json={"name": "Planted", "currency": "USD", "user_id": alice["id"]},
            headers=mallory["headers"],
        )
        via_query = await auth_client.post(
            HOMES,
            params={"user_id": alice["id"]},
            json={"name": "Planted", "currency": "USD"},
            headers=mallory["headers"],
        )

        assert forged.status_code == 422
        assert via_query.status_code == 201  # created, but for mallory
        assert (await auth_client.get(HOMES, headers=alice["headers"])).json() == {"items": []}

    async def test_responses_never_expose_owner_or_internal_columns(
        self, auth_client: AsyncClient
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        home = await created_home(auth_client, alice)
        responses = [
            await auth_client.get(HOMES, headers=alice["headers"]),
            await auth_client.get(f"{HOMES}/{home['id']}", headers=alice["headers"]),
        ]

        for response in responses:
            assert alice["id"] not in response.text
            assert "user_id" not in response.text
            assert "name_key" not in response.text


class TestErrors:
    async def test_database_errors_are_generic_500s(
        self, auth_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")

        async def boom(*_: object, **__: object) -> None:
            raise IntegrityError(
                "INSERT INTO homes (user_id, name) VALUES (...) password=hunter2", {}, Exception()
            )

        monkeypatch.setattr(HomeRepository, "add", boom)

        response = await create_home(auth_client, alice)

        assert response.status_code == 500
        assert response.json() == {
            "error": {"code": "internal_error", "message": "Internal server error"}
        }
        for leaked in ("INSERT", "homes", "hunter2", "IntegrityError"):
            assert leaked not in response.text


class TestRateLimiting:
    @pytest.fixture
    def limited(self, auth_app: FastAPI) -> FastAPI:
        auth_app.state.resource_rate_limits = DEFAULT_RESOURCE_RATE_LIMITS
        return auth_app

    async def test_create_per_user(self, limited: FastAPI, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        limit = DEFAULT_RESOURCE_RATE_LIMITS.homes_create_per_user.limit

        statuses = [
            (await create_home(auth_client, alice, name=f"H{i}")).status_code
            for i in range(limit + 1)
        ]

        assert statuses[:limit] == [201] * limit
        assert statuses[limit] == 429

    async def test_write_per_user_covers_patch_and_delete(
        self, limited: FastAPI, auth_client: AsyncClient
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        home = await created_home(auth_client, alice)
        url = f"{HOMES}/{home['id']}"
        limit = DEFAULT_RESOURCE_RATE_LIMITS.homes_write_per_user.limit
        for i in range(limit):
            await auth_client.patch(url, json={"name": f"N{i}"}, headers=alice["headers"])

        throttled = await auth_client.delete(url, headers=alice["headers"])

        assert throttled.status_code == 429
        assert int(throttled.headers["retry-after"]) > 0
        assert (await auth_client.get(url, headers=alice["headers"])).status_code == 200

    async def test_read_per_user_covers_list_and_get(
        self, limited: FastAPI, auth_client: AsyncClient
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        home = await created_home(auth_client, alice)
        limit = DEFAULT_RESOURCE_RATE_LIMITS.homes_read_per_user.limit
        for i in range(limit):
            url = HOMES if i % 2 else f"{HOMES}/{home['id']}"
            await auth_client.get(url, headers=alice["headers"])

        assert (await auth_client.get(HOMES, headers=alice["headers"])).status_code == 429

    async def test_limits_are_per_user_not_per_ip(
        self, limited: FastAPI, auth_client: AsyncClient
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        bob = await owner(auth_client, "bob@example.com")  # same client IP
        limit = DEFAULT_RESOURCE_RATE_LIMITS.homes_create_per_user.limit
        for i in range(limit + 1):
            await create_home(auth_client, alice, name=f"H{i}")

        assert (await create_home(auth_client, bob)).status_code == 201

    async def test_auth_endpoints_are_unaffected(
        self, limited: FastAPI, auth_client: AsyncClient
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        for i in range(DEFAULT_RESOURCE_RATE_LIMITS.homes_create_per_user.limit + 1):
            await create_home(auth_client, alice, name=f"H{i}")

        assert (await login(auth_client, email="alice@example.com")).status_code == 200


async def test_logs_never_contain_home_names_or_tokens(
    auth_client: AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    alice = await owner(auth_client, "alice@example.com")
    home = await created_home(auth_client, alice, name="Grandma Cottage 12 Elm St")
    url = f"{HOMES}/{home['id']}"
    await auth_client.patch(url, json={"name": "Secret Hideaway"}, headers=alice["headers"])
    await create_home(auth_client, alice, name="secret hideaway")
    await auth_client.get(HOMES, headers=alice["headers"])
    await auth_client.delete(url, headers=alice["headers"])

    for leaked in ("Grandma", "Elm St", "Hideaway", "hideaway", alice["access_token"]):
        assert leaked not in caplog.text
    assert f"home_id={home['id']}" in caplog.text


class TestProductionTransport:
    @pytest.fixture
    async def prod(self, db_session: AsyncSession) -> AsyncIterator[FastAPI]:
        async def override_db() -> AsyncIterator[AsyncSession]:
            yield db_session

        app = create_app(
            load_test_settings(environment="production", allowed_hosts=["api.example.com"])
        )
        app.dependency_overrides[get_db_session] = override_db
        app.state.password_hasher = fast_hasher()
        app.state.rate_limits = GENEROUS_RATE_LIMITS
        app.state.resource_rate_limits = GENEROUS_RESOURCE_RATE_LIMITS
        yield app
        await dispose_app(app)

    def client(self, app: FastAPI, base_url: str) -> AsyncClient:
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        return AsyncClient(transport=transport, base_url=base_url)

    async def test_homes_work_over_https_with_security_headers(self, prod: FastAPI) -> None:
        async with self.client(prod, "https://api.example.com") as c:
            await register(c, "alice@example.com")
            token = (await login(c, email="alice@example.com")).json()["access_token"]
            response = await c.post(
                HOMES,
                json={"name": "Main", "currency": "USD"},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert response.status_code == 201
        assert response.headers["strict-transport-security"].startswith("max-age=")
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"

    async def test_plain_http_is_rejected_before_auth(self, prod: FastAPI) -> None:
        async with self.client(prod, "http://api.example.com") as c:
            response = await c.get(HOMES)

        assert response.status_code == 400
        assert response.json()["error"]["code"] == "https_required"
