import uuid
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.tokens import AccessTokenService
from app.models.user_identity import UserIdentity
from tests.support.auth import API, bearer, login, register, registered_tokens
from tests.support.passwords import STRONG_PASSWORD

TOKEN_FIELDS = {"access_token", "refresh_token", "token_type", "expires_in"}
USER_FIELDS = {"id", "email", "auth_provider", "is_active", "created_at"}


def assert_token_response(body: dict[str, Any]) -> None:
    assert set(body) >= TOKEN_FIELDS
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 900


class TestRegister:
    async def test_returns_201_user_and_token_pair(self, auth_client: AsyncClient) -> None:
        response = await register(auth_client)

        assert response.status_code == 201
        body = response.json()
        assert set(body) == TOKEN_FIELDS | {"user"}
        assert_token_response(body)
        assert set(body["user"]) == USER_FIELDS
        assert body["user"]["email"] == "alice@example.com"
        assert body["user"]["auth_provider"] == "email"
        assert response.headers["cache-control"] == "no-store"

    async def test_email_is_normalized(
        self, auth_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        response = await register(auth_client, email="  Alice@EXAMPLE.com ")

        assert response.json()["user"]["email"] == "alice@example.com"
        stored = (await db_session.execute(select(UserIdentity.subject))).scalars().all()
        assert "alice@example.com" in stored

    async def test_access_token_works_immediately(self, auth_client: AsyncClient) -> None:
        tokens = await registered_tokens(auth_client)

        me = await auth_client.get(f"{API}/me", headers=bearer(tokens["access_token"]))

        assert me.status_code == 200
        assert me.json()["id"] == tokens["user"]["id"]

    async def test_duplicate_is_a_generic_409(self, auth_client: AsyncClient) -> None:
        await register(auth_client)

        response = await register(
            auth_client, email="ALICE@example.com", password="different strong phrase"
        )

        assert response.status_code == 409
        assert response.json() == {
            "error": {
                "code": "registration_unavailable",
                "message": "Unable to register with these details",
            }
        }

    async def test_weak_password_is_422_with_codes_only(self, auth_client: AsyncClient) -> None:
        response = await register(auth_client, password="password1234")

        assert response.status_code == 422
        body = response.json()
        assert body["error"]["code"] == "weak_password"
        assert body["error"]["violations"] == ["common"]
        assert "password1234" not in response.text

    async def test_invalid_email_is_422(self, auth_client: AsyncClient) -> None:
        response = await register(auth_client, email="not-an-email")

        assert response.status_code == 422
        assert "not-an-email" not in response.text

    async def test_client_cannot_choose_fields(self, auth_client: AsyncClient) -> None:
        response = await auth_client.post(
            f"{API}/register",
            json={
                "email": "alice@example.com",
                "password": STRONG_PASSWORD,
                "is_active": True,
                "auth_provider": "google",
                "id": str(uuid.uuid4()),
            },
        )

        assert response.status_code == 422


class TestLogin:
    async def test_success_returns_new_session_tokens(
        self, auth_client: AsyncClient, auth_app: Any
    ) -> None:
        registered = await registered_tokens(auth_client)

        response = await login(auth_client, email="ALICE@example.com")

        assert response.status_code == 200
        body = response.json()
        assert_token_response(body)
        assert body["user"]["id"] == registered["user"]["id"]
        access: AccessTokenService = auth_app.state.access_tokens
        first = access.decode(registered["access_token"]).session_id
        second = access.decode(body["access_token"]).session_id
        assert first != second

    async def test_wrong_password_is_401(self, auth_client: AsyncClient) -> None:
        await register(auth_client)

        response = await login(auth_client, password="wrong passphrase entirely")

        assert response.status_code == 401
        assert response.json() == {
            "error": {"code": "invalid_credentials", "message": "Invalid email or password"}
        }


class TestRefresh:
    async def test_rotates_tokens(self, auth_client: AsyncClient) -> None:
        tokens = await registered_tokens(auth_client)

        response = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}
        )

        assert response.status_code == 200
        body = response.json()
        assert set(body) == TOKEN_FIELDS
        assert body["refresh_token"] != tokens["refresh_token"]
        assert response.headers["cache-control"] == "no-store"

    async def test_invalid_refresh_token_is_generic_401(self, auth_client: AsyncClient) -> None:
        response = await auth_client.post(f"{API}/refresh", json={"refresh_token": "nope"})

        assert response.status_code == 401
        assert response.json() == {
            "error": {"code": "invalid_refresh_token", "message": "Invalid refresh token"}
        }

    async def test_refresh_token_must_be_in_body(self, auth_client: AsyncClient) -> None:
        tokens = await registered_tokens(auth_client)

        response = await auth_client.post(
            f"{API}/refresh", params={"refresh_token": tokens["refresh_token"]}
        )

        assert response.status_code == 422


class TestMe:
    async def test_returns_only_safe_fields(self, auth_client: AsyncClient) -> None:
        tokens = await registered_tokens(auth_client)

        response = await auth_client.get(f"{API}/me", headers=bearer(tokens["access_token"]))

        assert response.status_code == 200
        assert set(response.json()) == USER_FIELDS


class TestFlows:
    async def test_register_me_refresh_logout(self, auth_client: AsyncClient) -> None:
        tokens = await registered_tokens(auth_client)
        assert (
            await auth_client.get(f"{API}/me", headers=bearer(tokens["access_token"]))
        ).status_code == 200

        rotated = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert rotated.status_code == 200
        new = rotated.json()

        # Old refresh token: rejected (and, per strict reuse policy, the session is now revoked).
        replay = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert replay.status_code == 401

        logout = await auth_client.post(f"{API}/logout", headers=bearer(new["access_token"]))
        assert logout.status_code == 204
        after = await auth_client.post(
            f"{API}/refresh", json={"refresh_token": new["refresh_token"]}
        )
        assert after.status_code == 401
        me = await auth_client.get(f"{API}/me", headers=bearer(new["access_token"]))
        assert me.status_code == 401

    async def test_register_me_refresh_then_logout_without_reuse(
        self, auth_client: AsyncClient
    ) -> None:
        tokens = await registered_tokens(auth_client)
        new = (
            await auth_client.post(
                f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}
            )
        ).json()
        me = await auth_client.get(f"{API}/me", headers=bearer(new["access_token"]))
        assert me.status_code == 200

        assert (
            await auth_client.post(f"{API}/logout", headers=bearer(new["access_token"]))
        ).status_code == 204
        assert (
            await auth_client.post(f"{API}/refresh", json={"refresh_token": new["refresh_token"]})
        ).status_code == 401

    async def test_register_second_login_then_logout_all(self, auth_client: AsyncClient) -> None:
        phone = await registered_tokens(auth_client)
        tablet = (await login(auth_client)).json()

        response = await auth_client.post(
            f"{API}/logout-all", headers=bearer(tablet["access_token"])
        )

        assert response.status_code == 204
        for session in (phone, tablet):
            refresh = await auth_client.post(
                f"{API}/refresh", json={"refresh_token": session["refresh_token"]}
            )
            assert refresh.status_code == 401
            me = await auth_client.get(f"{API}/me", headers=bearer(session["access_token"]))
            assert me.status_code == 401

    async def test_logout_only_ends_the_current_session(self, auth_client: AsyncClient) -> None:
        phone = await registered_tokens(auth_client)
        tablet = (await login(auth_client)).json()

        await auth_client.post(f"{API}/logout", headers=bearer(phone["access_token"]))

        assert (
            await auth_client.get(f"{API}/me", headers=bearer(tablet["access_token"]))
        ).status_code == 200

    async def test_logout_is_idempotent(self, auth_client: AsyncClient) -> None:
        tokens = await registered_tokens(auth_client)
        headers = bearer(tokens["access_token"])

        first = await auth_client.post(f"{API}/logout", headers=headers)
        second = await auth_client.post(f"{API}/logout", headers=headers)

        assert (first.status_code, second.status_code) == (204, 204)
        assert second.content == b""
