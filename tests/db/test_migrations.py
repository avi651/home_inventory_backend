import configparser
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, inspect, text

from app.core.config import Settings
from app.models import Base
from tests.conftest import PROJECT_ROOT, alembic_config

ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"


@pytest.fixture
def migrator_engine(test_settings: Settings) -> Iterator[Engine]:
    engine = create_engine(test_settings.migration_database_url.get_secret_value())
    yield engine
    engine.dispose()


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        if not inspect(conn).has_table("alembic_version"):
            return None
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()


def test_alembic_ini_contains_no_database_url() -> None:
    parser = configparser.ConfigParser()
    parser.read(ALEMBIC_INI)

    assert not parser.get("alembic", "sqlalchemy.url", fallback="")


def leftover_objects(engine: Engine) -> dict[str, list[str]]:
    with engine.connect() as conn:
        tables = conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        ).scalars()
        types = conn.execute(
            text(
                "SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace "
                "WHERE n.nspname = 'public' AND t.typtype = 'e'"
            )
        ).scalars()
        return {
            "tables": sorted(set(tables) - {"alembic_version"}),
            "enum_types": sorted(types),
        }


def test_upgrade_downgrade_round_trip(test_settings: Settings, migrator_engine: Engine) -> None:
    """Regression: downgrade once left the auth_provider enum behind, breaking re-upgrade."""
    config = alembic_config(test_settings)
    head = ScriptDirectory.from_config(config).get_current_head()

    command.upgrade(config, "head")
    command.downgrade(config, "base")
    assert current_revision(migrator_engine) is None
    assert leftover_objects(migrator_engine) == {"tables": [], "enum_types": []}

    command.upgrade(config, "head")
    assert current_revision(migrator_engine) == head


def test_migrations_run_as_migrator_role(test_settings: Settings, migrator_engine: Engine) -> None:
    command.upgrade(alembic_config(test_settings), "head")

    with migrator_engine.connect() as conn:
        owner = conn.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename = 'alembic_version'")
        ).scalar_one()

    assert owner == "home_inventory_migrator"


def test_models_and_migrations_are_in_sync(
    test_settings: Settings, migrator_engine: Engine
) -> None:
    """Fails when a model changes without a matching migration."""
    command.upgrade(alembic_config(test_settings), "head")

    with migrator_engine.connect() as conn:
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        diff = compare_metadata(context, Base.metadata)

    assert diff == []
