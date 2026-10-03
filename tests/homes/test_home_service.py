"""HomeService: business rules, owner scoping, name uniqueness, cap, rollback."""

import logging
import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.home_fields import home_name_key
from app.exceptions.errors import HomeLimitReachedError, HomeNameTakenError, HomeNotFoundError
from app.models.home import Home
from app.services.home_service import MAX_HOMES_PER_USER, HomeService
from tests.support.factories import create_user


@pytest.fixture
def homes(db_session: AsyncSession) -> HomeService:
    return HomeService(db_session)


async def new_user_id(db: AsyncSession) -> uuid.UUID:
    """Plain ids, not ORM objects: the service rolls back on errors, which expires objects."""
    return (await create_user(db)).id


async def count_homes(db: AsyncSession, user_id: uuid.UUID) -> int:
    result = await db.execute(select(func.count()).select_from(Home).where(Home.user_id == user_id))
    return result.scalar_one()


async def reload(db: AsyncSession, home_id: uuid.UUID) -> Home:
    result = await db.execute(
        select(Home).where(Home.id == home_id).execution_options(populate_existing=True)
    )
    return result.scalar_one()


class TestCreate:
    async def test_stores_normalized_values_for_the_owner(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        user = await new_user_id(db_session)

        home = await homes.create(user, name="  Beach   House ", currency="eur")

        assert home.user_id == user
        assert (home.name, home.currency) == ("Beach House", "EUR")
        assert home.name_key == home_name_key("Beach House")

    async def test_case_variant_name_conflicts_for_the_same_user(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        user = await new_user_id(db_session)
        await homes.create(user, name="Home", currency="USD")

        with pytest.raises(HomeNameTakenError):
            await homes.create(user, name="HOME", currency="EUR")

        assert await count_homes(db_session, user) == 1

    async def test_different_users_may_share_a_name(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        alice, bob = await new_user_id(db_session), await new_user_id(db_session)
        await homes.create(alice, name="Home", currency="USD")

        home = await homes.create(bob, name="home", currency="USD")

        assert home.user_id == bob

    async def test_cap_is_enforced(self, homes: HomeService, db_session: AsyncSession) -> None:
        user = await new_user_id(db_session)
        for i in range(MAX_HOMES_PER_USER):
            await homes.create(user, name=f"Home {i}", currency="USD")

        with pytest.raises(HomeLimitReachedError):
            await homes.create(user, name="One too many", currency="USD")

        assert await count_homes(db_session, user) == MAX_HOMES_PER_USER

    async def test_cap_counts_current_homes_only(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        user = await new_user_id(db_session)
        created = [
            await homes.create(user, name=f"Home {i}", currency="USD")
            for i in range(MAX_HOMES_PER_USER)
        ]
        await homes.delete(user, created[0].id)

        home = await homes.create(user, name="Replacement", currency="USD")

        assert home.name == "Replacement"

    async def test_failed_commit_leaves_nothing_behind(
        self, homes: HomeService, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user = await new_user_id(db_session)

        async def fail() -> None:
            raise RuntimeError("commit failed")

        monkeypatch.setattr(db_session, "commit", fail)

        with pytest.raises(RuntimeError):
            await homes.create(user, name="Main", currency="USD")

        monkeypatch.undo()
        assert await count_homes(db_session, user) == 0

    async def test_other_constraint_failures_are_not_reported_as_name_conflicts(
        self, homes: HomeService
    ) -> None:
        with pytest.raises(IntegrityError):  # FK: owner does not exist -> generic 500
            await homes.create(uuid.uuid7(), name="Main", currency="USD")


class TestRead:
    async def test_get_own_home(self, homes: HomeService, db_session: AsyncSession) -> None:
        user = await new_user_id(db_session)
        created = await homes.create(user, name="Main", currency="USD")

        assert (await homes.get(user, created.id)).id == created.id

    @pytest.mark.parametrize("whose", ["other_user", "nobody"])
    async def test_other_or_unknown_home_is_not_found(
        self, homes: HomeService, db_session: AsyncSession, whose: str
    ) -> None:
        owner, attacker = await new_user_id(db_session), await new_user_id(db_session)
        created = await homes.create(owner, name="Main", currency="USD")
        home_id = created.id if whose == "other_user" else uuid.uuid7()

        with pytest.raises(HomeNotFoundError):
            await homes.get(attacker, home_id)

    async def test_list_returns_only_own_homes(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        alice, bob = await new_user_id(db_session), await new_user_id(db_session)
        mine = await homes.create(alice, name="Mine", currency="USD")
        await homes.create(bob, name="Theirs", currency="USD")

        assert [h.id for h in await homes.list(alice)] == [mine.id]


class TestUpdate:
    async def test_currency_only_keeps_the_name(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        user = await new_user_id(db_session)
        home = await homes.create(user, name="Main", currency="USD")

        updated = await homes.update(user, home.id, currency="gbp")

        assert (updated.name, updated.currency) == ("Main", "GBP")

    async def test_name_only_keeps_the_currency(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        user = await new_user_id(db_session)
        home = await homes.create(user, name="Main", currency="USD")

        updated = await homes.update(user, home.id, name=" Lake  House ")

        assert (updated.name, updated.currency) == ("Lake House", "USD")
        assert updated.name_key == home_name_key("Lake House")

    async def test_renaming_to_own_case_variant_is_allowed(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        user = await new_user_id(db_session)
        home = await homes.create(user, name="main", currency="USD")

        assert (await homes.update(user, home.id, name="Main")).name == "Main"

    async def test_renaming_onto_another_own_home_conflicts_and_changes_nothing(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        user = await new_user_id(db_session)
        await homes.create(user, name="Main", currency="USD")
        other_id = (await homes.create(user, name="Cabin", currency="USD")).id

        with pytest.raises(HomeNameTakenError):
            await homes.update(user, other_id, name="MAIN", currency="EUR")

        reloaded = await reload(db_session, other_id)
        assert (reloaded.name, reloaded.currency) == ("Cabin", "USD")

    async def test_other_users_home_is_not_found_and_unchanged(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        owner, attacker = await new_user_id(db_session), await new_user_id(db_session)
        home_id = (await homes.create(owner, name="Main", currency="USD")).id

        with pytest.raises(HomeNotFoundError):
            await homes.update(attacker, home_id, name="Pwned")

        assert (await reload(db_session, home_id)).name == "Main"

    async def test_nothing_to_update_is_refused(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        user = await new_user_id(db_session)
        home = await homes.create(user, name="Main", currency="USD")

        with pytest.raises(ValueError, match="nothing to update"):
            await homes.update(user, home.id)


class TestDelete:
    async def test_owner_deletes_and_second_delete_is_not_found(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        user = await new_user_id(db_session)
        home = await homes.create(user, name="Main", currency="USD")

        await homes.delete(user, home.id)

        assert await count_homes(db_session, user) == 0
        with pytest.raises(HomeNotFoundError):
            await homes.delete(user, home.id)

    async def test_other_users_home_is_not_found_and_kept(
        self, homes: HomeService, db_session: AsyncSession
    ) -> None:
        owner, attacker = await new_user_id(db_session), await new_user_id(db_session)
        home = await homes.create(owner, name="Main", currency="USD")

        with pytest.raises(HomeNotFoundError):
            await homes.delete(attacker, home.id)

        assert await count_homes(db_session, owner) == 1


async def test_logs_carry_ids_but_never_home_names(
    homes: HomeService, db_session: AsyncSession, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    user = await new_user_id(db_session)

    home_id = (await homes.create(user, name="Grandma Cottage 12 Elm St", currency="USD")).id
    await homes.update(user, home_id, name="Secret Hideaway")
    with pytest.raises(HomeNameTakenError):
        await homes.create(user, name="secret hideaway", currency="USD")
    await homes.delete(user, home_id)

    assert f"home_id={home_id}" in caplog.text
    for leaked in ("Grandma", "Elm St", "Hideaway", "hideaway"):
        assert leaked not in caplog.text
