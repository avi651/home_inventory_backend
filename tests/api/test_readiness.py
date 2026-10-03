from fastapi import FastAPI
from httpx import AsyncClient

from tests.conftest import AppFactory, make_client

UNREACHABLE_DB = (
    "postgresql+psycopg://home_inventory_app:not-the-password@127.0.0.1:1/home_inventory_test"
)


async def test_ready_when_database_reachable(client: AsyncClient) -> None:
    response = await client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


async def test_not_ready_when_database_unreachable(app_with_settings: AppFactory) -> None:
    async with make_client(app_with_settings(database_url=UNREACHABLE_DB)) as c:
        response = await c.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "database": "unavailable"}
    for leaked in ("127.0.0.1", "not-the-password", "psycopg", "refused", "home_inventory"):
        assert leaked not in response.text.lower()


async def test_liveness_does_not_depend_on_database(app_with_settings: AppFactory) -> None:
    async with make_client(app_with_settings(database_url=UNREACHABLE_DB)) as c:
        response = await c.get("/health")

    assert response.status_code == 200


async def test_database_connections_are_released(app: FastAPI, client: AsyncClient) -> None:
    for _ in range(3):
        await client.get("/health/ready")

    assert app.state.engine.pool.checkedout() == 0
