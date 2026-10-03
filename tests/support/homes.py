from typing import Any

from httpx import AsyncClient, Response

from tests.support.auth import bearer, guest_tokens, registered_tokens

HOMES = "/api/v1/homes"


async def owner(client: AsyncClient, email: str | None = None) -> dict[str, Any]:
    """A signed-in user (email account, or a guest when no email is given) with auth headers."""
    tokens = await (registered_tokens(client, email) if email else guest_tokens(client))
    return {**tokens, "headers": bearer(tokens["access_token"]), "id": tokens["user"]["id"]}


async def create_home(
    client: AsyncClient, who: dict[str, Any], name: str = "Main House", currency: str = "USD"
) -> Response:
    return await client.post(
        HOMES, json={"name": name, "currency": currency}, headers=who["headers"]
    )


async def created_home(client: AsyncClient, who: dict[str, Any], **kwargs: str) -> dict[str, Any]:
    response = await create_home(client, who, **kwargs)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body
