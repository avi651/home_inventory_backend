import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine


async def test_connects_to_test_database_as_runtime_role(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        row = (await conn.execute(text("SELECT current_database(), current_user"))).one()

    assert row == ("home_inventory_test", "home_inventory_app")


async def test_server_is_postgresql_17(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        version = (await conn.execute(text("SHOW server_version_num"))).scalar_one()

    assert 170000 <= int(version) < 180000


async def test_statement_timeout_is_bounded(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        timeout = (await conn.execute(text("SHOW statement_timeout"))).scalar_one()

    assert timeout != "0"


async def test_query_parameters_are_hidden_in_errors(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        with pytest.raises(DBAPIError) as exc_info:
            await conn.execute(
                text("SELECT 1 / 0 WHERE :value = :value"), {"value": "sensitive-param-value"}
            )

    assert "sensitive-param-value" not in str(exc_info.value)
