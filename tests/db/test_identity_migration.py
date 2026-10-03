"""D1 data migration: existing users' credentials move from users to user_identities.

Runs real Alembic upgrades/downgrades against the test database with committed seed data.
Each test truncates and restores the schema to head afterwards.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, inspect, text

from app.core.config import Settings
from tests.conftest import alembic_config
from tests.db.test_migrations import current_revision

PRE_D1 = "8bdc06075641"
D1 = "3f9c2a7d41b6"

FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
CREATED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

ALICE = uuid.UUID("01900000-0000-7000-8000-000000000001")
BOB = uuid.UUID("01900000-0000-7000-8000-000000000002")
GINA = uuid.UUID("01900000-0000-7000-8000-000000000003")
ADAM = uuid.UUID("01900000-0000-7000-8000-000000000004")
GUEST = uuid.UUID("01900000-0000-7000-8000-000000000005")

# Phase 1 shape: (id, auth_provider, email, password_hash, provider_subject, is_active)
SEED_USERS: list[tuple[uuid.UUID, str, str | None, str | None, str | None, bool]] = [
    (ALICE, "email", "alice@example.com", FAKE_HASH, None, True),
    (BOB, "email", "bob@example.com", FAKE_HASH + "b", None, False),
    (GINA, "google", "gina@example.com", None, "g-sub-1", True),
    (ADAM, "apple", None, None, "a-sub-1", True),
    (GUEST, "guest", None, None, None, True),
]
SNAPSHOT_OLD_USERS = (
    "SELECT id, auth_provider::text, email, password_hash, provider_subject, is_active, "
    "created_at, updated_at FROM users ORDER BY id"
)


@pytest.fixture
def migrator_engine(test_settings: Settings) -> Iterator[Engine]:
    engine = create_engine(test_settings.migration_database_url.get_secret_value())
    yield engine
    engine.dispose()


def truncate_users(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE users CASCADE"))


@pytest.fixture
def config(test_settings: Settings, migrator_engine: Engine) -> Iterator[Config]:
    """Empty database at the revision just before D1; restored to an empty head afterwards."""
    config = alembic_config(test_settings)
    command.upgrade(config, "head")
    truncate_users(migrator_engine)
    command.downgrade(config, PRE_D1)
    try:
        yield config
    finally:
        truncate_users(migrator_engine)
        command.upgrade(config, "head")


def seed_phase1_data(engine: Engine) -> None:
    with engine.begin() as conn:
        for user_id, provider, email, password_hash, subject, is_active in SEED_USERS:
            conn.execute(
                text(
                    "INSERT INTO users (id, auth_provider, email, password_hash, provider_subject,"
                    " is_active, created_at, updated_at) VALUES (:id, CAST(:provider AS"
                    " auth_provider), :email, :hash, :subject, :active, :created, :created)"
                ),
                {
                    "id": user_id,
                    "provider": provider,
                    "email": email,
                    "hash": password_hash,
                    "subject": subject,
                    "active": is_active,
                    "created": CREATED,
                },
            )
        conn.execute(
            text(
                "INSERT INTO auth_sessions (id, user_id, expires_at) "
                "VALUES (:sid, :uid, '2030-01-01T00:00:00Z')"
            ),
            {"sid": uuid.uuid7(), "uid": ALICE},
        )
        conn.execute(
            text(
                "INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at) "
                "SELECT :id, id, repeat('a', 64), expires_at FROM auth_sessions"
            ),
            {"id": uuid.uuid7()},
        )


def snapshot_old_users(engine: Engine) -> list[Any]:
    with engine.connect() as conn:
        return list(conn.execute(text(SNAPSHOT_OLD_USERS)).all())


def identities(engine: Engine) -> dict[uuid.UUID, tuple[Any, ...]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT user_id, provider::text, subject, email, password_hash, email_verified "
                "FROM user_identities"
            )
        ).all()
    assert len(rows) == len({row[0] for row in rows}), "a user got more than one identity"
    return {row[0]: tuple(row[1:]) for row in rows}


def scalar(engine: Engine, sql: str) -> Any:
    with engine.connect() as conn:
        return conn.execute(text(sql)).scalar_one()


class TestUpgradeWithExistingData:
    def test_every_credential_moves_to_exactly_one_identity(
        self, config: Config, migrator_engine: Engine
    ) -> None:
        seed_phase1_data(migrator_engine)

        command.upgrade(config, D1)

        assert identities(migrator_engine) == {
            ALICE: ("email", "alice@example.com", "alice@example.com", FAKE_HASH, False),
            BOB: ("email", "bob@example.com", "bob@example.com", FAKE_HASH + "b", False),
            GINA: ("google", "g-sub-1", "gina@example.com", None, False),
            ADAM: ("apple", "a-sub-1", None, None, False),
        }

    def test_no_user_is_lost_and_account_state_is_kept(
        self, config: Config, migrator_engine: Engine
    ) -> None:
        seed_phase1_data(migrator_engine)

        command.upgrade(config, D1)

        with migrator_engine.connect() as conn:
            users = conn.execute(
                text("SELECT id, is_guest, is_active, created_at FROM users ORDER BY id")
            ).all()
        assert [tuple(row) for row in users] == [
            (ALICE, False, True, CREATED),
            (BOB, False, False, CREATED),
            (GINA, False, True, CREATED),
            (ADAM, False, True, CREATED),
            (GUEST, True, True, CREATED),
        ]

    def test_sessions_and_refresh_tokens_survive(
        self, config: Config, migrator_engine: Engine
    ) -> None:
        seed_phase1_data(migrator_engine)

        command.upgrade(config, D1)

        assert scalar(migrator_engine, "SELECT count(*) FROM auth_sessions") == 1
        assert scalar(migrator_engine, "SELECT count(*) FROM refresh_tokens") == 1

    def test_identity_ids_are_unique_uuid7_and_never_orphaned(
        self, config: Config, migrator_engine: Engine
    ) -> None:
        seed_phase1_data(migrator_engine)

        command.upgrade(config, D1)

        with migrator_engine.connect() as conn:
            ids = conn.execute(text("SELECT id FROM user_identities")).scalars().all()
        assert len(set(ids)) == len(ids) == 4
        assert all(identity_id.version == 7 for identity_id in ids)
        orphans = (
            "SELECT count(*) FROM user_identities i LEFT JOIN users u ON u.id = i.user_id "
            "WHERE u.id IS NULL"
        )
        assert scalar(migrator_engine, orphans) == 0

    def test_old_credential_columns_and_enum_are_gone(
        self, config: Config, migrator_engine: Engine
    ) -> None:
        seed_phase1_data(migrator_engine)

        command.upgrade(config, D1)

        columns = {c["name"] for c in inspect(migrator_engine).get_columns("users")}
        assert not columns & {"email", "password_hash", "auth_provider", "provider_subject"}
        auth_provider_type = "SELECT count(*) FROM pg_type WHERE typname = 'auth_provider'"
        assert scalar(migrator_engine, auth_provider_type) == 0

    def test_empty_database_upgrades_cleanly(self, config: Config, migrator_engine: Engine) -> None:
        command.upgrade(config, D1)

        assert scalar(migrator_engine, "SELECT count(*) FROM user_identities") == 0


class TestDowngrade:
    def test_round_trip_restores_phase1_rows_exactly(
        self, config: Config, migrator_engine: Engine
    ) -> None:
        seed_phase1_data(migrator_engine)
        before = snapshot_old_users(migrator_engine)

        command.upgrade(config, D1)
        command.downgrade(config, PRE_D1)

        assert current_revision(migrator_engine) == PRE_D1
        assert snapshot_old_users(migrator_engine) == before
        assert not inspect(migrator_engine).has_table("user_identities")
        identity_type = "SELECT count(*) FROM pg_type WHERE typname = 'identity_provider'"
        assert scalar(migrator_engine, identity_type) == 0

    def test_re_upgrade_after_downgrade_does_not_duplicate_identities(
        self, config: Config, migrator_engine: Engine
    ) -> None:
        seed_phase1_data(migrator_engine)

        command.upgrade(config, D1)
        command.downgrade(config, PRE_D1)
        command.upgrade(config, D1)

        assert scalar(migrator_engine, "SELECT count(*) FROM user_identities") == 4
        assert scalar(migrator_engine, "SELECT count(*) FROM users") == 5

    def test_refuses_to_drop_linked_identities(
        self, config: Config, migrator_engine: Engine
    ) -> None:
        """Phase 1 holds one credential per user; a downgrade must not silently discard one."""
        seed_phase1_data(migrator_engine)
        command.upgrade(config, D1)
        with migrator_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO user_identities (id, user_id, provider, subject) "
                    "VALUES (gen_random_uuid(), :uid, 'google', 'g-sub-alice')"
                ),
                {"uid": ALICE},
            )

        with pytest.raises(RuntimeError, match="more than one identity"):
            command.downgrade(config, PRE_D1)

        assert current_revision(migrator_engine) == D1
        assert scalar(migrator_engine, "SELECT count(*) FROM user_identities") == 5

    def test_refuses_when_emails_would_collide(
        self, config: Config, migrator_engine: Engine
    ) -> None:
        """Phase 1 had one global email UNIQUE; an OAuth email may now repeat an email login."""
        seed_phase1_data(migrator_engine)
        command.upgrade(config, D1)
        with migrator_engine.begin() as conn:
            conn.execute(
                text("UPDATE user_identities SET email = 'alice@example.com' WHERE user_id = :u"),
                {"u": GINA},
            )

        with pytest.raises(RuntimeError, match="email"):
            command.downgrade(config, PRE_D1)

        assert current_revision(migrator_engine) == D1
