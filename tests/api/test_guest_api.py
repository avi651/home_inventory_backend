"""POST /auth/guest (Step 6): a new guest user with zero identities plus a normal token pair."""

import logging
import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rate_limit import DEFAULT_AUTH_RATE_LIMITS
from app.core.tokens import AccessTokenService
from app.models.auth_session import AuthSession
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_identity import UserIdentity
from tests.support.auth import API, bearer, guest, guest_tokens, registered_tokens

TOKEN_FIELDS = {"access_token", "refresh_token", "token_type", "expires_in"}
USER_FIELDS = {"id", "email", "auth_provider", "is_active", "created_at"}


def client_from(app: FastAPI, ip: str) -> AsyncClient:
    transport = ASGITransport(app=app, raise_app_exceptions=False, client=(ip, 40000))
    return AsyncClient(transport=transport, base_url="http://test")


async def count(db: AsyncSession, model: type[Any], *where: Any) -> int:
    return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


async def stored_user(db: AsyncSession, body: dict[str, Any]) -> User:
    user = await db.get(User, uuid.UUID(body["user"]["id"]))
    assert user is not None
    return user


class TestResponse:
    async def test_returns_201_with_token_pair_and_guest_user(
        self, auth_client: AsyncClient
    ) -> None:
        response = await guest(auth_client)

        assert response.status_code == 201
        body = response.json()
        assert set(body) == TOKEN_FIELDS | {"user"}
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == 900
        assert set(body["user"]) == USER_FIELDS
        assert body["user"]["email"] is None
        assert body["user"]["auth_provider"] == "guest"
        assert body["user"]["is_active"] is True
        assert response.headers["cache-control"] == "no-store"

    async def test_needs_no_body_and_ignores_client_supplied_ids(
        self, auth_client: AsyncClient
    ) -> None:
        """A client can never pick which user it becomes."""
        victim = await registered_tokens(auth_client)

        response = await auth_client.post(
            f"{API}/guest",
            params={"user_id": victim["user"]["id"]},
            json={"user_id": victim["user"]["id"], "is_guest": False, "email": "x@example.com"},
        )

        assert response.status_code == 201
        assert response.json()["user"]["id"] != victim["user"]["id"]
        assert response.json()["user"]["email"] is None

    async def test_an_existing_bearer_token_does_not_select_the_user(
        self, auth_client: AsyncClient
    ) -> None:
        victim = await registered_tokens(auth_client)

        response = await auth_client.post(f"{API}/guest", headers=bearer(victim["access_token"]))

        assert response.status_code == 201
        assert response.json()["user"]["id"] != victim["user"]["id"]

    async def test_never_returns_credential_data(self, auth_client: AsyncClient) -> None:
        response = await guest(auth_client)

        for marker in ("password", "$argon2", "subject", "identities", "is_guest"):
            assert marker not in response.text


class TestStoredState:
    async def test_creates_an_active_guest_user_with_zero_identities(
        self, auth_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        identities_before = await count(db_session, UserIdentity)

        body = await guest_tokens(auth_client)

        user = await stored_user(db_session, body)
        assert user.id.version == 7
        assert user.is_guest is True
        assert user.is_active is True
        assert await count(db_session, UserIdentity, UserIdentity.user_id == user.id) == 0
        # Nothing fabricated anywhere: no email, password hash or provider subject.
        assert await count(db_session, UserIdentity) == identities_before

    async def test_creates_one_live_session_with_one_refresh_token(
        self, auth_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        body = await guest_tokens(auth_client)
        user_id = uuid.UUID(body["user"]["id"])

        sessions = (
            (await db_session.execute(select(AuthSession).where(AuthSession.user_id == user_id)))
            .scalars()
            .all()
        )
        assert len(sessions) == 1
        assert sessions[0].revoked_at is None
        tokens = await count(db_session, RefreshToken, RefreshToken.session_id == sessions[0].id)
        assert tokens == 1

    async def test_every_call_creates_a_new_independent_guest(
        self, auth_client: AsyncClient, db_session: AsyncSession, auth_app: FastAPI
    ) -> None:
        identities_before = await count(db_session, UserIdentity)

        bodies = [await guest_tokens(auth_client) for _ in range(3)]

        user_ids = {b["user"]["id"] for b in bodies}
        access: AccessTokenService = auth_app.state.access_tokens
        session_ids = {access.decode(b["access_token"]).session_id for b in bodies}
        assert len(user_ids) == len(session_ids) == 3
        assert len({b["refresh_token"] for b in bodies}) == 3
        assert await count(db_session, UserIdentity) == identities_before


class TestTokens:
    async def test_access_token_names_the_guest_and_its_session(
        self, auth_client: AsyncClient, db_session: AsyncSession, auth_app: FastAPI
    ) -> None:
        body = await guest_tokens(auth_client)

        access: AccessTokenService = auth_app.state.access_tokens
        claims = access.decode(body["access_token"])
        assert str(claims.user_id) == body["user"]["id"]
        auth_session = await db_session.get(AuthSession, claims.session_id)
        assert auth_session is not None
        assert auth_session.user_id == claims.user_id

    async def test_access_token_works_on_me(self, auth_client: AsyncClient) -> None:
        body = await guest_tokens(auth_client)

        me = await auth_client.get(f"{API}/me", headers=bearer(body["access_token"]))

        assert me.status_code == 200
        assert me.json() == body["user"]

    async def test_refresh_rotates_and_reuse_revokes_the_session(
        self, auth_client: AsyncClient
    ) -> None:
        body = await guest_tokens(auth_client)

        rotated = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": body["refresh_token"]}
        )
        assert rotated.status_code == 200
        new = rotated.json()
        assert new["refresh_token"] != body["refresh_token"]
        assert (
            await auth_client.get(f"{API}/me", headers=bearer(new["access_token"]))
        ).status_code == 200

        reuse = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": body["refresh_token"]}
        )
        assert reuse.status_code == 401
        after = await auth_client.get(f"{API}/me", headers=bearer(new["access_token"]))
        assert after.status_code == 401

    async def test_logout_ends_the_guest_session(self, auth_client: AsyncClient) -> None:
        body = await guest_tokens(auth_client)

        out = await auth_client.post(f"{API}/logout", headers=bearer(body["access_token"]))

        assert out.status_code == 204
        me = await auth_client.get(f"{API}/me", headers=bearer(body["access_token"]))
        assert me.status_code == 401

    async def test_inactive_guest_is_locked_out(
        self, auth_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        body = await guest_tokens(auth_client)
        (await stored_user(db_session, body)).is_active = False
        await db_session.flush()

        me = await auth_client.get(f"{API}/me", headers=bearer(body["access_token"]))
        refreshed = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": body["refresh_token"]}
        )

        assert me.status_code == 401
        assert refreshed.status_code == 401


class TestIsolation:
    async def test_guest_sees_only_itself(self, auth_client: AsyncClient) -> None:
        alice = await registered_tokens(auth_client)
        body = await guest_tokens(auth_client)

        me = await auth_client.get(f"{API}/me", headers=bearer(body["access_token"]))

        assert me.json()["id"] == body["user"]["id"] != alice["user"]["id"]

    async def test_guest_logout_all_leaves_other_users_alone(
        self, auth_client: AsyncClient
    ) -> None:
        alice = await registered_tokens(auth_client)
        other_guest = await guest_tokens(auth_client)
        body = await guest_tokens(auth_client)

        out = await auth_client.post(f"{API}/logout-all", headers=bearer(body["access_token"]))

        assert out.status_code == 204
        for victim in (alice, other_guest):
            me = await auth_client.get(f"{API}/me", headers=bearer(victim["access_token"]))
            assert me.status_code == 200

    async def test_guest_refresh_token_cannot_borrow_another_users_session(
        self, auth_client: AsyncClient, auth_app: FastAPI
    ) -> None:
        alice = await registered_tokens(auth_client)
        body = await guest_tokens(auth_client)

        rotated = (
            await auth_client.post(f"{API}/refresh", json={"refresh_token": body["refresh_token"]})
        ).json()

        access: AccessTokenService = auth_app.state.access_tokens
        claims = access.decode(rotated["access_token"])
        assert str(claims.user_id) == body["user"]["id"] != alice["user"]["id"]


class TestRateLimiting:
    @pytest.fixture
    async def limited_app(self, auth_app: FastAPI) -> FastAPI:
        auth_app.state.rate_limits = DEFAULT_AUTH_RATE_LIMITS
        return auth_app

    async def test_guest_per_ip(self, limited_app: FastAPI, db_session: AsyncSession) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.guest_per_ip.limit
        users_before = await count(db_session, User)
        async with client_from(limited_app, "203.0.113.9") as client:
            statuses = [(await guest(client)).status_code for _ in range(limit + 1)]
            refused = await guest(client)

        assert statuses[:limit] == [201] * limit
        assert statuses[limit] == 429
        assert refused.json() == {
            "error": {"code": "too_many_requests", "message": "Too many requests"}
        }
        assert int(refused.headers["retry-after"]) > 0
        # Refused requests create nothing.
        assert await count(db_session, User) == users_before + limit

    async def test_limit_is_per_client(self, limited_app: FastAPI) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.guest_per_ip.limit
        async with client_from(limited_app, "203.0.113.10") as client:
            for _ in range(limit + 1):
                await guest(client)
        async with client_from(limited_app, "203.0.113.11") as other:
            assert (await guest(other)).status_code == 201

    async def test_guest_budget_is_separate_from_registration(self, limited_app: FastAPI) -> None:
        limit = DEFAULT_AUTH_RATE_LIMITS.guest_per_ip.limit
        async with client_from(limited_app, "203.0.113.12") as client:
            for _ in range(limit + 1):
                await guest(client)
            registered = await client.post(
                f"{API}/register",
                json={"email": "late@example.com", "password": "violet piano under the stairs"},
            )

        assert registered.status_code == 201


class TestNoLeaks:
    async def test_tokens_are_never_logged(
        self, auth_client: AsyncClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        body = await guest_tokens(auth_client)
        refreshed = (
            await auth_client.post(f"{API}/refresh", json={"refresh_token": body["refresh_token"]})
        ).json()
        await auth_client.get(f"{API}/me", headers=bearer(refreshed["access_token"]))

        logged = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
        for value in (
            body["access_token"],
            body["refresh_token"],
            refreshed["access_token"],
            refreshed["refresh_token"],
        ):
            assert value not in logged
        assert f"guest user created user_id={body['user']['id']}" in logged
