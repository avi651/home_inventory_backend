"""HomeRepository: every read and write is scoped by owner (IDOR prevention at the data layer)."""

import inspect
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.home_fields import home_name_key
from app.models.home import Home
from app.models.user import User
from app.repositories.home_repository import HomeRepository
from tests.support.factories import create_user


async def add_home(db: AsyncSession, user: User, name: str, currency: str = "USD") -> Home:
    return await HomeRepository(db).add(
        Home(user_id=user.id, name=name, name_key=home_name_key(name), currency=currency)
    )


async def still_exists(db: AsyncSession, home: Home) -> Home:
    """Re-read from the database (not the identity map)."""
    result = await db.execute(
        select(Home).where(Home.id == home.id).execution_options(populate_existing=True)
    )
    return result.scalar_one()


class TestReads:
    async def test_owner_gets_their_home(self, db_session: AsyncSession) -> None:
        owner = await create_user(db_session)
        home = await add_home(db_session, owner, "Main")

        found = await HomeRepository(db_session).get_for_user(user_id=owner.id, home_id=home.id)

        assert found is not None
        assert found.id == home.id

    async def test_other_users_home_is_invisible(self, db_session: AsyncSession) -> None:
        owner, attacker = await create_user(db_session), await create_user(db_session)
        home = await add_home(db_session, owner, "Main")

        found = await HomeRepository(db_session).get_for_user(user_id=attacker.id, home_id=home.id)

        assert found is None

    async def test_unknown_id_is_none(self, db_session: AsyncSession) -> None:
        owner = await create_user(db_session)

        repo = HomeRepository(db_session)
        assert await repo.get_for_user(user_id=owner.id, home_id=uuid.uuid7()) is None

    async def test_list_contains_only_own_homes_oldest_first(
        self, db_session: AsyncSession
    ) -> None:
        owner, other = await create_user(db_session), await create_user(db_session)
        first = await add_home(db_session, owner, "First")
        await add_home(db_session, other, "Theirs")
        second = await add_home(db_session, owner, "Second")

        homes = await HomeRepository(db_session).list_for_user(owner.id)

        assert [h.id for h in homes] == [first.id, second.id]

    async def test_count_is_per_owner(self, db_session: AsyncSession) -> None:
        owner, other = await create_user(db_session), await create_user(db_session)
        for name in ("A", "B"):
            await add_home(db_session, owner, name)
        await add_home(db_session, other, "C")

        assert await HomeRepository(db_session).count_for_user_locked(owner.id) == 2


class TestWrites:
    async def test_owner_can_update(self, db_session: AsyncSession) -> None:
        owner = await create_user(db_session)
        home = await add_home(db_session, owner, "Main")

        updated = await HomeRepository(db_session).update_for_user(
            user_id=owner.id, home_id=home.id, values={"currency": "EUR"}
        )

        assert updated is not None
        assert (updated.name, updated.currency) == ("Main", "EUR")

    async def test_update_of_other_users_home_changes_nothing(
        self, db_session: AsyncSession
    ) -> None:
        owner, attacker = await create_user(db_session), await create_user(db_session)
        home = await add_home(db_session, owner, "Main")

        updated = await HomeRepository(db_session).update_for_user(
            user_id=attacker.id,
            home_id=home.id,
            values={"name": "Pwned", "name_key": home_name_key("Pwned")},
        )

        assert updated is None
        assert (await still_exists(db_session, home)).name == "Main"

    async def test_owner_can_delete(self, db_session: AsyncSession) -> None:
        owner = await create_user(db_session)
        home = await add_home(db_session, owner, "Main")

        deleted = await HomeRepository(db_session).delete_for_user(
            user_id=owner.id, home_id=home.id
        )

        assert deleted is True
        assert await HomeRepository(db_session).list_for_user(owner.id) == []

    async def test_delete_of_other_users_home_changes_nothing(
        self, db_session: AsyncSession
    ) -> None:
        owner, attacker = await create_user(db_session), await create_user(db_session)
        home = await add_home(db_session, owner, "Main")

        deleted = await HomeRepository(db_session).delete_for_user(
            user_id=attacker.id, home_id=home.id
        )

        assert deleted is False
        assert (await still_exists(db_session, home)).id == home.id


def test_every_read_and_write_requires_an_owner() -> None:
    """Guard: no repository method can reach a home without the owner's user_id."""
    public = {
        name: member
        for name, member in inspect.getmembers(HomeRepository, inspect.isfunction)
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
    for name, member in public.items():
        if name != "add":  # add() takes a Home whose user_id the service set
            assert "user_id" in inspect.signature(member).parameters, name
