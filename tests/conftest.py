from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import Environment, Settings
from app.core.database import create_db_engine
from app.main import create_app

TEST_ENV_FILE = Path(__file__).resolve().parent.parent / ".env.test"


def load_test_settings(**overrides: Any) -> Settings:
    settings = Settings(_env_file=TEST_ENV_FILE, **overrides)
    # Hard guard: tests must never run against a non-test database.
    assert settings.database_url.get_secret_value().endswith("_test")
    assert settings.migration_database_url.get_secret_value().endswith("_test")
    return settings


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    settings = load_test_settings()
    assert settings.environment is Environment.TEST
    return settings


@pytest.fixture(scope="session")
async def engine(test_settings: Settings) -> AsyncIterator[AsyncEngine]:
    """Runtime-role engine (DML only), shared across the session."""
    engine = create_db_engine(test_settings)
    yield engine
    await engine.dispose()


async def dispose_app(app: FastAPI) -> None:
    await app.state.engine.dispose()


@pytest.fixture
async def app(test_settings: Settings) -> AsyncIterator[FastAPI]:
    app = create_app(test_settings)
    yield app
    await dispose_app(app)


def make_client(app: FastAPI) -> AsyncClient:
    # raise_app_exceptions=False: assert on what a real client would receive for 500s.
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with make_client(app) as c:
        yield c


AppFactory = Callable[..., FastAPI]


@pytest.fixture
async def app_with_settings() -> AsyncIterator[AppFactory]:
    """Build an app from .env.test with overrides, e.g. environment='production'."""
    created: list[FastAPI] = []

    def factory(**overrides: Any) -> FastAPI:
        app = create_app(load_test_settings(**overrides))
        created.append(app)
        return app

    yield factory
    for app in created:
        await dispose_app(app)
