"""RoomRepository: every read and write is scoped through the full chain User -> Home -> Room.

A room is reachable only when the caller names its home *and* owns that home. Any other
combination (another user's home, the owner's other home, unknown ids) is "not found" and
mutates nothing.
"""

import inspect
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from psycopg.errors import LockNotAvailable
from sqlalchemy import delete, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.home_fields import home_name_key
from app.core.room_fields import room_name_key
from app.models.home import Home
from app.models.room import Room
from app.models.user import User
from app.repositories.room_repository import RoomRepository
from tests.support.factories import create_user


async def add_home(db: AsyncSession, user: User, name: str) -> Home:
    home = Home(user_id=user.id, name=name, name_key=home_name_key(name), currency="USD")
    db.add(home)
    await db.flush()
    return home


async def add_room(db: AsyncSession, user: User, home: Home, name: str) -> Room:
    room = await RoomRepository(db).add(
        user_id=user.id, home_id=home.id, name=name, name_key=room_name_key(name)
    )
    assert room is not None
    return room


async def snapshot(db: AsyncSession) -> set[tuple[uuid.UUID, uuid.UUID, str]]:
    """Every room as stored in the database (not the identity map)."""
    result = await db.execute(
        select(Room.id, Room.home_id, Room.name).execution_options(populate_existing=True)
    )
    return {(row.id, row.home_id, row.name) for row in result}


@dataclass
class World:
    """owner has homes A (rooms a1, a2) and B (room b1); attacker has home X (room x1)."""

    owner: User
    attacker: User
    home_a: Home
    home_b: Home
    home_x: Home
    a1: Room
    a2: Room
    b1: Room
    x1: Room


@pytest.fixture
async def world(db_session: AsyncSession) -> World:
    owner, attacker = await create_user(db_session), await create_user(db_session)
    home_a = await add_home(db_session, owner, "A")
    home_b = await add_home(db_session, owner, "B")
    home_x = await add_home(db_session, attacker, "X")
    return World(
        owner=owner,
        attacker=attacker,
        home_a=home_a,
        home_b=home_b,
        home_x=home_x,
        a1=await add_room(db_session, owner, home_a, "Kitchen"),
        a2=await add_room(db_session, owner, home_a, "Garage"),
        b1=await add_room(db_session, owner, home_b, "Kitchen"),
        x1=await add_room(db_session, attacker, home_x, "Kitchen"),
    )


# (user, home, room) combinations that must all be "not found". Built lazily from the world.
DENIED = {
    "other_user_via_their_home": lambda w: (w.attacker.id, w.home_a.id, w.a1.id),
    "other_user_via_own_home": lambda w: (w.attacker.id, w.home_x.id, w.a1.id),
    "own_room_under_own_other_home": lambda w: (w.owner.id, w.home_b.id, w.a1.id),
    "other_users_room_under_own_home": lambda w: (w.owner.id, w.home_a.id, w.x1.id),
    "own_room_via_other_users_home": lambda w: (w.owner.id, w.home_x.id, w.a1.id),
    "unknown_room": lambda w: (w.owner.id, w.home_a.id, uuid.uuid7()),
    "unknown_home": lambda w: (w.owner.id, uuid.uuid7(), w.a1.id),
    "unknown_user": lambda w: (uuid.uuid7(), w.home_a.id, w.a1.id),
}


class TestAdd:
    async def test_owner_adds_room_to_own_home(
        self, db_session: AsyncSession, world: World
    ) -> None:
        room = await RoomRepository(db_session).add(
            user_id=world.owner.id,
            home_id=world.home_b.id,
            name="Attic",
            name_key=room_name_key("Attic"),
        )

        assert room is not None
        assert (room.home_id, room.name, room.name_key) == (
            world.home_b.id,
            "Attic",
            room_name_key("Attic"),
        )
        assert room.id.version == 7
        assert (room.id, world.home_b.id, "Attic") in await snapshot(db_session)

    @pytest.mark.parametrize(
        "case",
        {
            "other_users_home": lambda w: (w.attacker.id, w.home_a.id),
            "unknown_home": lambda w: (w.owner.id, uuid.uuid7()),
            "unknown_user": lambda w: (uuid.uuid7(), w.home_a.id),
        }.items(),
        ids=lambda case: case[0],
    )
    async def test_cannot_add_outside_own_homes(
        self, db_session: AsyncSession, world: World, case: tuple[str, object]
    ) -> None:
        user_id, home_id = case[1](world)  # type: ignore[operator]
        before = await snapshot(db_session)

        room = await RoomRepository(db_session).add(
            user_id=user_id, home_id=home_id, name="Planted", name_key=room_name_key("Planted")
        )

        assert room is None
        assert await snapshot(db_session) == before


class TestGet:
    async def test_owner_gets_room_through_its_home(
        self, db_session: AsyncSession, world: World
    ) -> None:
        room = await RoomRepository(db_session).get_for_user(
            user_id=world.owner.id, home_id=world.home_a.id, room_id=world.a1.id
        )

        assert room is not None
        assert room.id == world.a1.id

    @pytest.mark.parametrize("case", DENIED.items(), ids=list(DENIED))
    async def test_denied_combinations_are_not_found(
        self, db_session: AsyncSession, world: World, case: tuple[str, object]
    ) -> None:
        user_id, home_id, room_id = case[1](world)  # type: ignore[operator]

        room = await RoomRepository(db_session).get_for_user(
            user_id=user_id, home_id=home_id, room_id=room_id
        )

        assert room is None


class TestList:
    async def test_owner_lists_only_that_homes_rooms_oldest_first(
        self, db_session: AsyncSession, world: World
    ) -> None:
        repo = RoomRepository(db_session)

        rooms_a = await repo.list_for_user(user_id=world.owner.id, home_id=world.home_a.id)
        rooms_b = await repo.list_for_user(user_id=world.owner.id, home_id=world.home_b.id)

        assert [r.id for r in rooms_a] == [world.a1.id, world.a2.id]
        assert [r.id for r in rooms_b] == [world.b1.id]

    @pytest.mark.parametrize(
        "case",
        {
            "other_users_home": lambda w: (w.attacker.id, w.home_a.id),
            "own_user_other_users_home": lambda w: (w.owner.id, w.home_x.id),
            "unknown_home": lambda w: (w.owner.id, uuid.uuid7()),
            "unknown_user": lambda w: (uuid.uuid7(), w.home_a.id),
        }.items(),
        ids=lambda case: case[0],
    )
    async def test_list_outside_own_homes_is_empty(
        self, db_session: AsyncSession, world: World, case: tuple[str, object]
    ) -> None:
        user_id, home_id = case[1](world)  # type: ignore[operator]

        assert (
            await RoomRepository(db_session).list_for_user(user_id=user_id, home_id=home_id) == []
        )

    async def test_order_is_created_at_then_id(self, db_session: AsyncSession) -> None:
        """created_at decides; equal timestamps fall back to id, so pages are deterministic."""
        owner = await create_user(db_session)
        home = await add_home(db_session, owner, "Main")
        t0, t1 = datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 2, tzinfo=UTC)
        low, mid, high = sorted(uuid.uuid7() for _ in range(3))
        # Insertion order and id order both disagree with the expected order.
        for room_id, name, created_at in (
            (high, "Late", t1),
            (mid, "Tie high", t0),
            (low, "Tie low", t0),
        ):
            db_session.add(
                Room(
                    id=room_id,
                    home_id=home.id,
                    name=name,
                    name_key=room_name_key(name),
                    created_at=created_at,
                )
            )
        await db_session.flush()

        rooms = await RoomRepository(db_session).list_for_user(user_id=owner.id, home_id=home.id)

        assert [r.id for r in rooms] == [low, mid, high]


class TestCount:
    async def test_counts_only_that_homes_rooms(
        self, db_session: AsyncSession, world: World
    ) -> None:
        repo = RoomRepository(db_session)

        assert (
            await repo.count_for_user_locked(user_id=world.owner.id, home_id=world.home_a.id) == 2
        )
        assert (
            await repo.count_for_user_locked(user_id=world.owner.id, home_id=world.home_b.id) == 1
        )

    async def test_empty_owned_home_counts_zero(self, db_session: AsyncSession) -> None:
        owner = await create_user(db_session)
        home = await add_home(db_session, owner, "Empty")

        count = await RoomRepository(db_session).count_for_user_locked(
            user_id=owner.id, home_id=home.id
        )

        assert count == 0

    @pytest.mark.parametrize(
        "case",
        {
            "other_users_home": lambda w: (w.attacker.id, w.home_a.id),
            "unknown_home": lambda w: (w.owner.id, uuid.uuid7()),
            "unknown_user": lambda w: (uuid.uuid7(), w.home_a.id),
        }.items(),
        ids=lambda case: case[0],
    )
    async def test_count_outside_own_homes_is_none(
        self, db_session: AsyncSession, world: World, case: tuple[str, object]
    ) -> None:
        """None (not 0): the caller must treat the home as not found, not as empty."""
        user_id, home_id = case[1](world)  # type: ignore[operator]

        count = await RoomRepository(db_session).count_for_user_locked(
            user_id=user_id, home_id=home_id
        )

        assert count is None


class TestUpdate:
    async def test_owner_renames_room(self, db_session: AsyncSession, world: World) -> None:
        room = await RoomRepository(db_session).update_for_user(
            user_id=world.owner.id,
            home_id=world.home_a.id,
            room_id=world.a1.id,
            name="Pantry",
            name_key=room_name_key("Pantry"),
        )

        assert room is not None
        assert (room.id, room.home_id, room.name, room.name_key) == (
            world.a1.id,
            world.home_a.id,
            "Pantry",
            room_name_key("Pantry"),
        )
        assert (world.a1.id, world.home_a.id, "Pantry") in await snapshot(db_session)

    @pytest.mark.parametrize("case", DENIED.items(), ids=list(DENIED))
    async def test_denied_combinations_change_nothing(
        self, db_session: AsyncSession, world: World, case: tuple[str, object]
    ) -> None:
        user_id, home_id, room_id = case[1](world)  # type: ignore[operator]
        before = await snapshot(db_session)

        room = await RoomRepository(db_session).update_for_user(
            user_id=user_id,
            home_id=home_id,
            room_id=room_id,
            name="Pwned",
            name_key=room_name_key("Pwned"),
        )

        assert room is None
        assert await snapshot(db_session) == before


class TestDelete:
    async def test_owner_deletes_room(self, db_session: AsyncSession, world: World) -> None:
        before = await snapshot(db_session)

        deleted = await RoomRepository(db_session).delete_for_user(
            user_id=world.owner.id, home_id=world.home_a.id, room_id=world.a1.id
        )

        assert deleted is True
        assert await snapshot(db_session) == before - {(world.a1.id, world.home_a.id, "Kitchen")}

    @pytest.mark.parametrize("case", DENIED.items(), ids=list(DENIED))
    async def test_denied_combinations_delete_nothing(
        self, db_session: AsyncSession, world: World, case: tuple[str, object]
    ) -> None:
        user_id, home_id, room_id = case[1](world)  # type: ignore[operator]
        before = await snapshot(db_session)

        deleted = await RoomRepository(db_session).delete_for_user(
            user_id=user_id, home_id=home_id, room_id=room_id
        )

        assert deleted is False
        assert await snapshot(db_session) == before


# Users committed for real by TestHomeRowLock; removed (homes cascade) after each test.
_lock_test_users: list[uuid.UUID] = []


class TestHomeRowLock:
    """count_for_user_locked must hold FOR UPDATE on the owned parent home until commit.

    Needs committed rows visible to a second connection, so it bypasses the rollback fixture.
    """

    @pytest.fixture
    async def factory(
        self, migrated_database: None, engine: AsyncEngine
    ) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        async with factory() as db:
            await db.execute(delete(User).where(User.id.in_(_lock_test_users)))
            await db.commit()
        _lock_test_users.clear()

    async def committed_home(self, factory: async_sessionmaker[AsyncSession]) -> Home:
        async with factory() as db:
            owner = await create_user(db)
            home = await add_home(db, owner, "Locked")
            await db.commit()
        _lock_test_users.append(owner.id)
        return home

    @staticmethod
    async def home_is_locked(factory: async_sessionmaker[AsyncSession], home_id: uuid.UUID) -> bool:
        async with factory() as other:
            try:
                await other.execute(
                    select(Home.id).where(Home.id == home_id).with_for_update(nowait=True)
                )
            except DBAPIError as exc:
                if isinstance(exc.orig, LockNotAvailable):
                    return True
                raise
            finally:
                await other.rollback()
        return False

    async def test_owner_count_locks_the_home_row(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        home = await self.committed_home(factory)

        async with factory() as db:
            count = await RoomRepository(db).count_for_user_locked(
                user_id=home.user_id, home_id=home.id
            )
            assert count == 0
            assert await self.home_is_locked(factory, home.id)
            await db.rollback()

        assert not await self.home_is_locked(factory, home.id)

    async def test_other_user_cannot_lock_someone_elses_home(
        self, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        """Otherwise anyone could stall a victim's room creates by guessing their home id."""
        home = await self.committed_home(factory)

        async with factory() as db:
            count = await RoomRepository(db).count_for_user_locked(
                user_id=uuid.uuid7(), home_id=home.id
            )
            assert count is None
            assert not await self.home_is_locked(factory, home.id)
            await db.rollback()


def test_every_method_requires_the_full_ownership_chain() -> None:
    """Guard: no repository method can reach a room without the owner and the parent home.

    Ownership ids are keyword-only, so a caller cannot swap home_id and room_id positionally.
    """
    public = {
        name: member
        for name, member in inspect.getmembers(RoomRepository, inspect.isfunction)
        if not name.startswith("_")
    }

    assert set(public) == {
        "add",
        "count_for_user_locked",
        "delete_for_user",
        "get_for_user",
        "list_for_user",
        "update_for_user",
    }
    room_level = {"get_for_user", "update_for_user", "delete_for_user"}
    for name, member in public.items():
        params = inspect.signature(member).parameters
        required = {"user_id", "home_id"} | ({"room_id"} if name in room_level else set())
        for param in required:
            assert param in params, (name, param)
            assert params[param].kind is inspect.Parameter.KEYWORD_ONLY, (name, param)
            assert params[param].default is inspect.Parameter.empty, (name, param)
    # A room can be renamed, never re-parented: no free-form values on update.
    assert set(inspect.signature(RoomRepository.update_for_user).parameters) == {
        "self",
        "user_id",
        "home_id",
        "room_id",
        "name",
        "name_key",
    }
