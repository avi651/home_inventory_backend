"""Homes API behaviour: CRUD, validation, conflicts, response shapes."""

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.user_identity import IdentityProvider
from app.services.home_service import MAX_HOMES_PER_USER
from app.services.identity_service import IdentityService
from tests.support.homes import HOMES, create_home, created_home, owner

HOME_FIELDS = {"id", "name", "currency", "created_at", "updated_at"}
NOT_FOUND = {"error": {"code": "not_found", "message": "Not found"}}
NAME_TAKEN = {
    "error": {"code": "home_name_taken", "message": "A home with this name already exists"}
}
LIMIT = {"error": {"code": "home_limit_reached", "message": "Home limit reached"}}


class TestCreate:
    async def test_returns_201_with_the_normalized_home(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")

        response = await create_home(auth_client, alice, name="  Beach   House ", currency="eur")

        assert response.status_code == 201
        body = response.json()
        assert set(body) == HOME_FIELDS
        assert (body["name"], body["currency"]) == ("Beach House", "EUR")
        assert uuid.UUID(body["id"]).version == 7
        assert response.headers["cache-control"] == "no-store"

    async def test_unicode_names_round_trip(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        name = "\U0001f3e0 \u6771\u4eac Caf\u00e9"

        body = await created_home(auth_client, alice, name=name)

        assert body["name"] == name

    async def test_case_insensitive_duplicate_is_409(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        await created_home(auth_client, alice, name="Home")

        response = await create_home(auth_client, alice, name="HOME")

        assert response.status_code == 409
        assert response.json() == NAME_TAKEN

    async def test_same_name_for_different_users_is_fine(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        bob = await owner(auth_client)
        await created_home(auth_client, alice, name="Home")

        assert (await create_home(auth_client, bob, name="Home")).status_code == 201

    async def test_cap_of_50_is_409(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        for i in range(MAX_HOMES_PER_USER):
            await created_home(auth_client, alice, name=f"Home {i}")

        response = await create_home(auth_client, alice, name="One too many")

        assert response.status_code == 409
        assert response.json() == LIMIT

    @pytest.mark.parametrize(
        "body",
        [
            {"currency": "USD"},
            {"name": "Main"},
            {"name": "", "currency": "USD"},
            {"name": "   ", "currency": "USD"},
            {"name": "a" * 101, "currency": "USD"},
            {"name": "a" * 100_000, "currency": "USD"},
            {"name": "bad\x00name", "currency": "USD"},
            {"name": "bidi\u202eemoH", "currency": "USD"},
            {"name": None, "currency": "USD"},
            {"name": 123, "currency": "USD"},
            {"name": "Main", "currency": "XYZ"},
            {"name": "Main", "currency": "US"},
            {"name": "Main", "currency": None},
            {"name": "Main", "currency": "USD", "user_id": str(uuid.uuid4())},
            {"name": "Main", "currency": "USD", "id": str(uuid.uuid4())},
            {"name": "Main", "currency": "USD", "name_key": "0" * 64},
            {"name": "Main", "currency": "USD", "created_at": "2020-01-01T00:00:00Z"},
        ],
    )
    async def test_invalid_input_is_422_without_echo(
        self, auth_client: AsyncClient, body: dict[str, Any]
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")

        response = await auth_client.post(HOMES, json=body, headers=alice["headers"])

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"
        assert "bad\\u0000name" not in response.text
        assert "aaaaaaaaaa" not in response.text
        assert "XYZ" not in response.text

    async def test_sql_injection_payload_is_just_a_name(
        self, auth_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        payload = "x'); DROP TABLE homes; --"

        body = await created_home(auth_client, alice, name=payload)

        assert body["name"] == payload
        count = await db_session.execute(text("SELECT count(*) FROM homes"))
        assert count.scalar_one() >= 1


class TestList:
    async def test_empty_list_is_wrapped(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")

        response = await auth_client.get(HOMES, headers=alice["headers"])

        assert response.status_code == 200
        assert response.json() == {"items": []}
        assert response.headers["cache-control"] == "no-store"

    async def test_lists_own_homes_oldest_first(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        first = await created_home(auth_client, alice, name="First")
        second = await created_home(auth_client, alice, name="Second")

        body = (await auth_client.get(HOMES, headers=alice["headers"])).json()

        assert [h["id"] for h in body["items"]] == [first["id"], second["id"]]
        assert all(set(h) == HOME_FIELDS for h in body["items"])


class TestGet:
    async def test_returns_the_home(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        home = await created_home(auth_client, alice)

        response = await auth_client.get(f"{HOMES}/{home['id']}", headers=alice["headers"])

        assert response.status_code == 200
        assert response.json() == home

    async def test_unknown_home_is_the_generic_404(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")

        response = await auth_client.get(f"{HOMES}/{uuid.uuid7()}", headers=alice["headers"])

        assert response.status_code == 404
        assert response.json() == NOT_FOUND

    @pytest.mark.parametrize(
        "bad_id", ["not-a-uuid", "12345", "' OR '1'='1", "00000000-0000-0000-0000-00000000000g"]
    )
    async def test_malformed_ids_are_a_safe_422(
        self, auth_client: AsyncClient, bad_id: str
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")

        response = await auth_client.get(f"{HOMES}/{bad_id}", headers=alice["headers"])

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"
        assert bad_id not in response.text


class TestUpdate:
    async def test_currency_only_keeps_the_name(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        home = await created_home(auth_client, alice, name="Main", currency="USD")

        response = await auth_client.patch(
            f"{HOMES}/{home['id']}", json={"currency": "jpy"}, headers=alice["headers"]
        )

        assert response.status_code == 200
        body = response.json()
        assert (body["name"], body["currency"]) == ("Main", "JPY")
        assert body["updated_at"] >= home["updated_at"]
        assert body["created_at"] == home["created_at"]

    async def test_name_only_keeps_the_currency(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        home = await created_home(auth_client, alice, name="Main", currency="CAD")

        body = (
            await auth_client.patch(
                f"{HOMES}/{home['id']}", json={"name": " Lake House "}, headers=alice["headers"]
            )
        ).json()

        assert (body["name"], body["currency"]) == ("Lake House", "CAD")

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"name": None},
            {"currency": None},
            {"name": None, "currency": "USD"},
            {"name": ""},
            {"currency": "XYZ"},
            {"user_id": str(uuid.uuid4())},
            {"name": "Ok", "user_id": str(uuid.uuid4())},
            {"id": str(uuid.uuid4())},
        ],
    )
    async def test_invalid_patch_is_422_and_changes_nothing(
        self, auth_client: AsyncClient, body: dict[str, Any]
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")
        home = await created_home(auth_client, alice, name="Main", currency="USD")

        response = await auth_client.patch(
            f"{HOMES}/{home['id']}", json=body, headers=alice["headers"]
        )
        after = (await auth_client.get(f"{HOMES}/{home['id']}", headers=alice["headers"])).json()

        assert response.status_code == 422
        assert after == home

    async def test_rename_onto_another_home_is_409(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        await created_home(auth_client, alice, name="Main")
        cabin = await created_home(auth_client, alice, name="Cabin")

        response = await auth_client.patch(
            f"{HOMES}/{cabin['id']}", json={"name": "main"}, headers=alice["headers"]
        )

        assert response.status_code == 409
        assert response.json() == NAME_TAKEN

    async def test_unknown_home_is_404(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")

        response = await auth_client.patch(
            f"{HOMES}/{uuid.uuid7()}", json={"name": "X"}, headers=alice["headers"]
        )

        assert response.status_code == 404
        assert response.json() == NOT_FOUND


class TestDelete:
    async def test_204_then_gone(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")
        home = await created_home(auth_client, alice)
        url = f"{HOMES}/{home['id']}"

        deleted = await auth_client.delete(url, headers=alice["headers"])

        assert deleted.status_code == 204
        assert deleted.content == b""
        assert (await auth_client.get(url, headers=alice["headers"])).status_code == 404
        again = await auth_client.delete(url, headers=alice["headers"])
        assert again.status_code == 404
        assert again.json() == NOT_FOUND


class TestGuests:
    async def test_guest_owns_homes_and_keeps_them_after_upgrade(
        self, auth_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        guest = await owner(auth_client)
        home = await created_home(auth_client, guest, name="Starter")
        user_id = uuid.UUID(guest["id"])
        user = await db_session.get(User, user_id)
        assert user is not None
        assert user.is_guest
        # Upgrade (the future linking API does this): same user id, data stays attached.
        await IdentityService(db_session).link(user_id, IdentityProvider.GOOGLE, "g-upgraded-guest")
        user.is_guest = False
        await db_session.commit()

        listed = (await auth_client.get(HOMES, headers=guest["headers"])).json()

        assert [h["id"] for h in listed["items"]] == [home["id"]]
