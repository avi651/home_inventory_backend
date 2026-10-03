"""Global 1 MiB request-body limit: 413 payload_too_large, before auth, parsing or the DB."""

from collections.abc import AsyncIterator

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import MAX_REQUEST_BODY_BYTES
from app.models.home import Home
from tests.support.homes import HOMES, owner

TOO_LARGE = {"error": {"code": "payload_too_large", "message": "Request body too large"}}
LOGIN = "/api/v1/auth/login"


def json_of_size(size: int) -> bytes:
    """A syntactically valid JSON object of exactly `size` bytes."""
    prefix, suffix = b'{"name": "', b'", "currency": "USD"}'
    return prefix + b"a" * (size - len(prefix) - len(suffix)) + suffix


async def chunks(body: bytes, chunk_size: int = 64 * 1024) -> AsyncIterator[bytes]:
    for start in range(0, len(body), chunk_size):
        yield body[start : start + chunk_size]


def test_limit_is_one_mebibyte() -> None:
    assert MAX_REQUEST_BODY_BYTES == 1024 * 1024


class TestDeclaredLength:
    async def test_oversized_body_is_413_before_authentication(
        self, auth_client: AsyncClient
    ) -> None:
        response = await auth_client.post(
            HOMES,
            content=json_of_size(MAX_REQUEST_BODY_BYTES + 1),
            headers={"content-type": "application/json"},
        )

        assert response.status_code == 413
        assert response.json() == TOO_LARGE
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "no-store"

    async def test_oversized_authenticated_request_creates_nothing(
        self, auth_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        alice = await owner(auth_client, "alice@example.com")

        response = await auth_client.post(
            HOMES,
            content=json_of_size(5 * MAX_REQUEST_BODY_BYTES),
            headers={**alice["headers"], "content-type": "application/json"},
        )

        assert response.status_code == 413
        count = await db_session.execute(select(func.count()).select_from(Home))
        assert count.scalar_one() == 0

    async def test_body_at_the_limit_reaches_validation(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")

        response = await auth_client.post(
            HOMES,
            content=json_of_size(MAX_REQUEST_BODY_BYTES),
            headers={**alice["headers"], "content-type": "application/json"},
        )

        assert response.status_code == 422  # name too long: validation, not the size limit

    async def test_existing_100kb_password_case_still_reaches_validation(
        self, auth_client: AsyncClient
    ) -> None:
        response = await auth_client.post(
            LOGIN, json={"email": "a@example.com", "password": "x" * 100_000}
        )

        assert response.status_code == 422


class TestStreamedBody:
    async def test_chunked_body_without_length_is_cut_off(self, auth_client: AsyncClient) -> None:
        """No Content-Length (chunked): the limit is enforced while reading."""
        response = await auth_client.post(
            HOMES,
            content=chunks(json_of_size(MAX_REQUEST_BODY_BYTES + 10)),
            headers={"content-type": "application/json"},
        )

        assert response.status_code == 413
        assert response.json() == TOO_LARGE

    async def test_small_chunked_body_passes(self, auth_client: AsyncClient) -> None:
        alice = await owner(auth_client, "alice@example.com")

        response = await auth_client.post(
            HOMES,
            content=chunks(b'{"name": "Main", "currency": "USD"}', chunk_size=5),
            headers={**alice["headers"], "content-type": "application/json"},
        )

        assert response.status_code == 201


@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_requests_without_bodies_are_unaffected(
    auth_client: AsyncClient, method: str
) -> None:
    alice = await owner(auth_client, "alice@example.com")

    response = await auth_client.request(method, HOMES, headers=alice["headers"])

    assert response.status_code in (200, 405)
