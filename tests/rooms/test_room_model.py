"""rooms table: database-level guarantees (parent-home FK, cascade, CHECKs, per-home name key).

Ownership is User -> Home -> Room: a room has no user_id of its own.
"""

import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.home_fields import home_name_key
from app.core.room_fields import room_name_key
from app.models.home import Home
from app.models.room import Room
from app.models.user import User
from tests.support.factories import create_user


async def create_home(db: AsyncSession, user: User | None = None, name: str = "Main House") -> Home:
    owner = user or await create_user(db)
    row = Home(user_id=owner.id, name=name, name_key=home_name_key(name), currency="USD")
    db.add(row)
    await db.flush()
    return row


def room(parent: Home, **overrides: Any) -> Room:
    name = overrides.pop("name", "Kitchen")
    values: dict[str, Any] = {"home_id": parent.id, "name": name, "name_key": room_name_key(name)}
    values.update(overrides)
    return Room(**values)


async def save(db: AsyncSession, row: Room) -> Room:
    db.add(row)
    await db.flush()
    await db.refresh(row)
    return row


async def assert_rejected(db: AsyncSession, row: Room, constraint: str) -> None:
    db.add(row)
    with pytest.raises(IntegrityError, match=constraint):
        await db.flush()
    await db.rollback()


async def room_ids(db: AsyncSession, *homes: Home) -> set[uuid.UUID]:
    query = select(Room.id).where(Room.home_id.in_([h.id for h in homes]))
    return set((await db.execute(query)).scalars().all())


class TestShape:
    def test_columns_are_exactly_the_locked_set(self) -> None:
        assert set(Room.__table__.columns.keys()) == {
            "id",
            "home_id",
            "name",
            "name_key",
            "created_at",
            "updated_at",
        }

    def test_room_has_no_user_id(self) -> None:
        """Ownership is derived through the parent home, never stored on the room."""
        assert "user_id" not in Room.__table__.columns


class TestIdentityAndTimestamps:
    async def test_uuid7_and_database_timestamps(self, db_session: AsyncSession) -> None:
        row = await save(db_session, room(await create_home(db_session)))

        assert row.id.version == 7
        db_now = (await db_session.execute(select(func.clock_timestamp()))).scalar_one()
        assert db_now - row.created_at < timedelta(minutes=1)
        assert row.updated_at >= row.created_at

    async def test_updated_at_changes_on_update(self, db_session: AsyncSession) -> None:
        row = await save(db_session, room(await create_home(db_session)))
        created, before = row.created_at, row.updated_at

        row.name, row.name_key = "Pantry", room_name_key("Pantry")
        await db_session.flush()
        await db_session.refresh(row)

        assert row.updated_at > before
        assert row.created_at == created


class TestParentHome:
    async def test_home_is_required(self, db_session: AsyncSession) -> None:
        parent = await create_home(db_session)

        await assert_rejected(db_session, room(parent, home_id=None), "home_id")

    async def test_home_must_exist(self, db_session: AsyncSession) -> None:
        parent = await create_home(db_session)

        await assert_rejected(
            db_session, room(parent, home_id=uuid.uuid7()), "fk_rooms_home_id_homes"
        )

    async def test_deleting_a_home_deletes_its_rooms_only(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)
        doomed = await create_home(db_session, user, "A")
        kept_home = await create_home(db_session, user, "B")
        await save(db_session, room(doomed, name="Kitchen"))
        await save(db_session, room(doomed, name="Garage"))
        kept = await save(db_session, room(kept_home, name="Kitchen"))

        await db_session.execute(text("DELETE FROM homes WHERE id = :id"), {"id": doomed.id})

        assert await room_ids(db_session, doomed, kept_home) == {kept.id}

    async def test_deleting_a_user_deletes_rooms_through_their_homes(
        self, db_session: AsyncSession
    ) -> None:
        owner, other = await create_user(db_session), await create_user(db_session)
        owner_home = await create_home(db_session, owner)
        other_home = await create_home(db_session, other)
        await save(db_session, room(owner_home))
        kept = await save(db_session, room(other_home))

        await db_session.execute(text("DELETE FROM users WHERE id = :id"), {"id": owner.id})

        assert await room_ids(db_session, owner_home, other_home) == {kept.id}


class TestNameRules:
    async def test_same_name_key_twice_in_one_home_is_rejected(
        self, db_session: AsyncSession
    ) -> None:
        parent = await create_home(db_session)
        await save(db_session, room(parent, name="Kitchen"))

        await assert_rejected(
            db_session,
            room(parent, name="KITCHEN", name_key=room_name_key("Kitchen")),
            "uq_rooms_home_id_name_key",
        )

    async def test_homes_of_the_same_user_may_share_a_room_name(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        await save(db_session, room(await create_home(db_session, user, "A"), name="Kitchen"))

        row = await save(db_session, room(await create_home(db_session, user, "B"), name="Kitchen"))

        assert row.id is not None

    async def test_homes_of_different_users_may_share_a_room_name(
        self, db_session: AsyncSession
    ) -> None:
        await save(db_session, room(await create_home(db_session), name="Kitchen"))

        row = await save(db_session, room(await create_home(db_session), name="Kitchen"))

        assert row.id is not None

    @pytest.mark.parametrize("name", ["", " padded", "padded ", "  "])
    async def test_blank_or_untrimmed_names_are_rejected(
        self, db_session: AsyncSession, name: str
    ) -> None:
        parent = await create_home(db_session)

        await assert_rejected(db_session, room(parent, name=name), "ck_rooms_name_trimmed")

    async def test_max_length_name_is_accepted(self, db_session: AsyncSession) -> None:
        row = await save(db_session, room(await create_home(db_session), name="a" * 100))

        assert row.name == "a" * 100

    async def test_overlong_name_is_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(room(await create_home(db_session), name="a" * 101))

        with pytest.raises(DataError, match="too long"):
            await db_session.flush()
        await db_session.rollback()

    @pytest.mark.parametrize("key", ["Kitchen", "A" * 64, "a" * 63, ""])
    async def test_name_key_must_be_a_sha256_digest(
        self, db_session: AsyncSession, key: str
    ) -> None:
        parent = await create_home(db_session)

        await assert_rejected(db_session, room(parent, name_key=key), "ck_rooms_name_key_format")

    async def test_name_key_is_required(self, db_session: AsyncSession) -> None:
        parent = await create_home(db_session)

        await assert_rejected(db_session, room(parent, name_key=None), "name_key")


async def test_sql_injection_payload_is_stored_as_data(db_session: AsyncSession) -> None:
    payload = "x'); DROP TABLE rooms; --"
    row = await save(db_session, room(await create_home(db_session), name=payload))

    found = (await db_session.execute(select(Room).where(Room.id == row.id))).scalar_one()

    assert found.name == payload


async def test_repr_has_no_user_content(db_session: AsyncSession) -> None:
    row = await save(db_session, room(await create_home(db_session), name="Secret Vault"))

    assert "Secret" not in repr(row)
    assert row.name_key not in repr(row)
