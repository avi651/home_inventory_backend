"""homes table: database-level guarantees (owner FK, cascade, CHECKs, per-user name key)."""

import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.home_fields import home_name_key
from app.models.home import Home
from app.models.user import User
from tests.support.factories import create_user


def home(user: User, **overrides: Any) -> Home:
    name = overrides.pop("name", "Main House")
    values: dict[str, Any] = {
        "user_id": user.id,
        "name": name,
        "name_key": home_name_key(name),
        "currency": "USD",
    }
    values.update(overrides)
    return Home(**values)


async def save(db: AsyncSession, row: Home) -> Home:
    db.add(row)
    await db.flush()
    await db.refresh(row)
    return row


async def assert_rejected(db: AsyncSession, row: Home, constraint: str) -> None:
    db.add(row)
    with pytest.raises(IntegrityError, match=constraint):
        await db.flush()
    await db.rollback()


class TestIdentityAndTimestamps:
    async def test_uuid7_and_database_timestamps(self, db_session: AsyncSession) -> None:
        row = await save(db_session, home(await create_user(db_session)))

        assert row.id.version == 7
        db_now = (await db_session.execute(select(func.clock_timestamp()))).scalar_one()
        assert db_now - row.created_at < timedelta(minutes=1)
        assert row.updated_at >= row.created_at

    async def test_updated_at_changes_on_update(self, db_session: AsyncSession) -> None:
        row = await save(db_session, home(await create_user(db_session)))
        created, before = row.created_at, row.updated_at

        row.currency = "EUR"
        await db_session.flush()
        await db_session.refresh(row)

        assert row.updated_at > before
        assert row.created_at == created


class TestOwnership:
    async def test_owner_is_required(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)

        await assert_rejected(db_session, home(user, user_id=None), "user_id")

    async def test_owner_must_exist(self, db_session: AsyncSession) -> None:
        user = await create_user(db_session)

        await assert_rejected(
            db_session, home(user, user_id=uuid.uuid7()), "fk_homes_user_id_users"
        )

    async def test_deleting_the_owner_deletes_their_homes_only(
        self, db_session: AsyncSession
    ) -> None:
        owner, other = await create_user(db_session), await create_user(db_session)
        await save(db_session, home(owner, name="A"))
        await save(db_session, home(owner, name="B"))
        kept = await save(db_session, home(other, name="A"))

        await db_session.execute(text("DELETE FROM users WHERE id = :id"), {"id": owner.id})

        remaining = (
            (
                await db_session.execute(
                    select(Home.id).where(Home.user_id.in_([owner.id, other.id]))
                )
            )
            .scalars()
            .all()
        )
        assert remaining == [kept.id]


class TestNameRules:
    async def test_same_name_key_twice_for_one_user_is_rejected(
        self, db_session: AsyncSession
    ) -> None:
        user = await create_user(db_session)
        await save(db_session, home(user, name="Home"))

        await assert_rejected(
            db_session,
            home(user, name="HOME", name_key=home_name_key("Home")),
            "uq_homes_user_id_name_key",
        )

    async def test_different_users_may_share_a_name(self, db_session: AsyncSession) -> None:
        await save(db_session, home(await create_user(db_session), name="Home"))

        row = await save(db_session, home(await create_user(db_session), name="Home"))

        assert row.id is not None

    @pytest.mark.parametrize("name", ["", " padded", "padded ", "  "])
    async def test_blank_or_untrimmed_names_are_rejected(
        self, db_session: AsyncSession, name: str
    ) -> None:
        user = await create_user(db_session)

        await assert_rejected(db_session, home(user, name=name), "ck_homes_name")

    async def test_overlong_name_is_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(home(await create_user(db_session), name="a" * 101))

        with pytest.raises(DataError, match="too long"):
            await db_session.flush()
        await db_session.rollback()

    @pytest.mark.parametrize("key", ["Home", "A" * 64, "a" * 63, ""])
    async def test_name_key_must_be_a_sha256_digest(
        self, db_session: AsyncSession, key: str
    ) -> None:
        user = await create_user(db_session)

        await assert_rejected(db_session, home(user, name_key=key), "ck_homes_name_key_format")


class TestCurrencyRules:
    @pytest.mark.parametrize("currency", ["usd", "US", "U5D", ""])
    async def test_currency_must_be_three_uppercase_letters(
        self, db_session: AsyncSession, currency: str
    ) -> None:
        user = await create_user(db_session)

        await assert_rejected(db_session, home(user, currency=currency), "ck_homes_currency_format")

    async def test_overlong_currency_is_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(home(await create_user(db_session), currency="USDX"))

        with pytest.raises(DataError, match="too long"):
            await db_session.flush()
        await db_session.rollback()


async def test_sql_injection_payload_is_stored_as_data(db_session: AsyncSession) -> None:
    payload = "x'); DROP TABLE homes; --"
    row = await save(db_session, home(await create_user(db_session), name=payload))

    found = (await db_session.execute(select(Home).where(Home.id == row.id))).scalar_one()

    assert found.name == payload


async def test_repr_has_no_user_content(db_session: AsyncSession) -> None:
    row = await save(db_session, home(await create_user(db_session), name="Grandma's Cottage"))

    assert "Grandma" not in repr(row)
