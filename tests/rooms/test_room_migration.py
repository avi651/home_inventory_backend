"""rooms migration: schema at head, chained after homes, reversible without touching homes.

Runs real Alembic upgrades/downgrades against the test database with committed seed data.
Each downgrade test truncates and restores the schema to head afterwards.
"""

import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, String, create_engine, inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import Settings
from app.core.home_fields import home_name_key
from app.core.room_fields import room_name_key
from tests.conftest import alembic_config

HOMES = "7c4d1e9a2b60"
ROOMS = "a3e9d27f5c18"

USER = uuid.UUID("01900000-0000-7000-8000-0000000000a1")
HOME = uuid.UUID("01900000-0000-7000-8000-0000000000b1")
ROOM = uuid.UUID("01900000-0000-7000-8000-0000000000c1")


@pytest.fixture
def migrator_engine(test_settings: Settings) -> Iterator[Engine]:
    engine = create_engine(test_settings.migration_database_url.get_secret_value())
    yield engine
    engine.dispose()


@pytest.fixture
def config(test_settings: Settings, migrator_engine: Engine) -> Iterator[Config]:
    """Empty database at head; truncated and restored to head afterwards."""
    config = alembic_config(test_settings)
    command.upgrade(config, "head")
    truncate_users(migrator_engine)
    try:
        yield config
    finally:
        truncate_users(migrator_engine)
        command.upgrade(config, "head")


def truncate_users(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE users CASCADE"))


def seed_user_home_room(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO users (id, is_guest) VALUES (:id, true)"), {"id": USER})
        conn.execute(
            text(
                "INSERT INTO homes (id, user_id, name, name_key, currency) "
                "VALUES (:id, :user_id, 'Main House', :key, 'USD')"
            ),
            {"id": HOME, "user_id": USER, "key": home_name_key("Main House")},
        )
        conn.execute(
            text(
                "INSERT INTO rooms (id, home_id, name, name_key) "
                "VALUES (:id, :home_id, 'Kitchen', :key)"
            ),
            {"id": ROOM, "home_id": HOME, "key": room_name_key("Kitchen")},
        )


def test_rooms_revision_is_head_and_follows_homes(test_settings: Settings) -> None:
    scripts = ScriptDirectory.from_config(alembic_config(test_settings))

    assert scripts.get_current_head() == ROOMS
    assert scripts.get_revision(ROOMS).down_revision == HOMES


class TestSchemaAtHead:
    @pytest.fixture(autouse=True)
    def _at_head(self, config: Config) -> None:
        """Every schema check runs against a freshly upgraded database."""

    def test_columns_are_exactly_the_locked_set_and_not_null(self, migrator_engine: Engine) -> None:
        columns = {c["name"]: c for c in inspect(migrator_engine).get_columns("rooms")}

        assert set(columns) == {"id", "home_id", "name", "name_key", "created_at", "updated_at"}
        assert not any(c["nullable"] for c in columns.values())
        name_type, key_type = columns["name"]["type"], columns["name_key"]["type"]
        assert isinstance(name_type, String)
        assert isinstance(key_type, String)
        assert (name_type.length, key_type.length) == (100, 64)

    def test_primary_key_is_id(self, migrator_engine: Engine) -> None:
        pk = inspect(migrator_engine).get_pk_constraint("rooms")

        assert (pk["name"], pk["constrained_columns"]) == ("pk_rooms", ["id"])

    def test_home_fk_cascades_on_delete(self, migrator_engine: Engine) -> None:
        [fk] = inspect(migrator_engine).get_foreign_keys("rooms")

        assert fk["name"] == "fk_rooms_home_id_homes"
        assert fk["constrained_columns"] == ["home_id"]
        assert (fk["referred_table"], fk["referred_columns"]) == ("homes", ["id"])
        assert fk["options"].get("ondelete") == "CASCADE"

    def test_name_key_is_unique_per_home(self, migrator_engine: Engine) -> None:
        uniques = inspect(migrator_engine).get_unique_constraints("rooms")

        assert [(u["name"], u["column_names"]) for u in uniques] == [
            ("uq_rooms_home_id_name_key", ["home_id", "name_key"])
        ]

    def test_check_constraints(self, migrator_engine: Engine) -> None:
        checks = {c["name"] for c in inspect(migrator_engine).get_check_constraints("rooms")}

        assert checks == {"ck_rooms_name_trimmed", "ck_rooms_name_key_format"}

    async def test_runtime_role_has_dml_but_not_ownership(self, engine: AsyncEngine) -> None:
        async with engine.connect() as conn:
            owned, privileges = (
                await conn.execute(
                    text(
                        "SELECT (SELECT tableowner = current_user FROM pg_tables "
                        "WHERE schemaname = 'public' AND tablename = 'rooms'), "
                        "array_agg(p ORDER BY p) FILTER "
                        "(WHERE has_table_privilege(current_user, 'rooms', p)) "
                        "FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS p"
                    )
                )
            ).one()

        assert owned is False
        assert privileges == ["DELETE", "INSERT", "SELECT", "UPDATE"]


def test_downgrade_drops_rooms_and_keeps_homes_data(
    config: Config, migrator_engine: Engine
) -> None:
    seed_user_home_room(migrator_engine)

    command.downgrade(config, HOMES)

    assert not inspect(migrator_engine).has_table("rooms")
    with migrator_engine.connect() as conn:
        homes = conn.execute(text("SELECT id FROM homes")).scalars().all()
    assert homes == [HOME]

    command.upgrade(config, "head")

    with migrator_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM rooms")).scalar_one() == 0
        assert conn.execute(text("SELECT id FROM homes")).scalars().all() == [HOME]
