from typing import Any

from httpx import AsyncClient, Response

from tests.support.passwords import STRONG_PASSWORD

API = "/api/v1/auth"


async def register(
    client: AsyncClient, email: str = "alice@example.com", password: str = STRONG_PASSWORD
) -> Response:
    return await client.post(f"{API}/register", json={"email": email, "password": password})


async def login(
    client: AsyncClient, email: str = "alice@example.com", password: str = STRONG_PASSWORD
) -> Response:
    return await client.post(f"{API}/login", json={"email": email, "password": password})


async def registered_tokens(
    client: AsyncClient, email: str = "alice@example.com"
) -> dict[str, Any]:
    response = await register(client, email)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def bearer(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}
