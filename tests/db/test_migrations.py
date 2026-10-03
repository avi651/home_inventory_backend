import configparser
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, inspect, text

from app.core.config import Settings
from tests.conftest import PROJECT_ROOT

ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"


def alembic_config(settings: Settings) -> Config:
    config = Config(str(ALEMBIC_INI))
    config.attributes["database_url"] = settings.migration_database_url.get_secret_value()
    config.attributes["configure_logger"] = False  # keep pytest's logging setup intact
    return config


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


def test_upgrade_downgrade_round_trip(test_settings: Settings, migrator_engine: Engine) -> None:
    config = alembic_config(test_settings)
    head = ScriptDirectory.from_config(config).get_current_head()

    command.downgrade(config, "base")
    assert current_revision(migrator_engine) is None

    command.upgrade(config, "head")
    assert current_revision(migrator_engine) == head


def test_migrations_run_as_migrator_role(test_settings: Settings, migrator_engine: Engine) -> None:
    command.upgrade(alembic_config(test_settings), "head")

    with migrator_engine.connect() as conn:
        owner = conn.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename = 'alembic_version'")
        ).scalar_one()

    assert owner == "home_inventory_migrator"
