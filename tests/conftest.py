from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.config import Environment, Settings
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


@pytest.fixture
def app(test_settings: Settings) -> FastAPI:
    return create_app(test_settings)


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
def app_with_settings() -> AppFactory:
    """Build an app from .env.test with overrides, e.g. environment='production'."""

    def factory(**overrides: Any) -> FastAPI:
        return create_app(load_test_settings(**overrides))

    return factory
