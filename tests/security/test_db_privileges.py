"""The runtime role must be least-privilege: DML only, no DDL, no escalation."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine


async def test_runtime_role_is_not_privileged(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            )
        ).one()

    assert row == (False, False, False, False)


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE TABLE should_not_exist (id int)",
        "CREATE SCHEMA should_not_exist",
        "CREATE DATABASE should_not_exist",
        "CREATE ROLE should_not_exist",
    ],
)
async def test_runtime_role_cannot_run_ddl(engine: AsyncEngine, ddl: str) -> None:
    # AUTOCOMMIT: CREATE DATABASE is refused inside a transaction before privileges are checked.
    async with engine.connect() as conn:
        await conn.execution_options(isolation_level="AUTOCOMMIT")
        with pytest.raises(ProgrammingError, match="permission denied"):
            await conn.execute(text(ddl))
