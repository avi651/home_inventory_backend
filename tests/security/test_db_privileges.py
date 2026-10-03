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


async def test_runtime_role_can_read_and_write_users(
    migrated_database: None, engine: AsyncEngine
) -> None:
    async with engine.connect() as conn:
        privileges = (
            await conn.execute(
                text(
                    "SELECT array_agg(p ORDER BY p) FROM unnest("
                    "ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS p "
                    "WHERE has_table_privilege(current_user, 'users', p)"
                )
            )
        ).scalar_one()

    assert privileges == ["DELETE", "INSERT", "SELECT", "UPDATE"]


@pytest.mark.parametrize(
    "statement",
    [
        "DROP TABLE users",
        "ALTER TABLE users ADD COLUMN is_admin boolean",
        "ALTER TABLE user_identities DROP CONSTRAINT ck_user_identities_provider_fields",
        "ALTER TABLE user_identities DROP CONSTRAINT uq_user_identities_provider_subject",
        "TRUNCATE users",
    ],
)
async def test_runtime_role_cannot_alter_schema_objects(
    migrated_database: None, engine: AsyncEngine, statement: str
) -> None:
    async with engine.connect() as conn:
        await conn.execution_options(isolation_level="AUTOCOMMIT")
        with pytest.raises(ProgrammingError, match=r"must be owner|permission denied"):
            await conn.execute(text(statement))


async def test_runtime_role_has_dml_but_not_ownership_on_every_app_table(
    migrated_database: None, engine: AsyncEngine
) -> None:
    """Covers tables added by later migrations automatically."""
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    # has_table_privilege('A,B') is true if ANY is held, so check each one.
                    "SELECT t.tablename, t.tableowner = current_user, bool_and("
                    "has_table_privilege(current_user, quote_ident(t.tablename), p)) "
                    "FROM pg_tables t, unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS p "
                    "WHERE t.schemaname = 'public' AND t.tablename <> 'alembic_version' "
                    "GROUP BY t.tablename, t.tableowner"
                )
            )
        ).all()

    assert {"users", "user_identities", "auth_sessions", "refresh_tokens"} <= {
        row[0] for row in rows
    }
    for table, is_owner, has_dml in rows:
        assert has_dml, f"runtime role lacks DML on {table}"
        assert not is_owner, f"runtime role owns {table}"
