from datetime import timedelta

from sqlalchemy import func, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


async def save(session: AsyncSession, user: User) -> User:
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return user


class TestIdentityAndTimestamps:
    async def test_primary_key_is_uuid7(self, db_session: AsyncSession) -> None:
        user = await save(db_session, User())

        assert user.id.version == 7

    async def test_ids_are_time_ordered(self, db_session: AsyncSession) -> None:
        first = await save(db_session, User())
        second = await save(db_session, User())

        assert first.id < second.id

    async def test_timestamps_are_set_by_database(self, db_session: AsyncSession) -> None:
        user = await save(db_session, User())

        assert user.created_at.tzinfo is not None
        assert user.updated_at >= user.created_at
        db_now = (await db_session.execute(select(func.clock_timestamp()))).scalar_one()
        assert db_now - user.created_at < timedelta(minutes=1)

    async def test_updated_at_changes_on_update(self, db_session: AsyncSession) -> None:
        user = await save(db_session, User())
        created, before = user.created_at, user.updated_at

        user.is_active = False
        await db_session.flush()
        await db_session.refresh(user)

        assert user.updated_at > before
        assert user.created_at == created

    async def test_defaults(self, db_session: AsyncSession) -> None:
        user = await save(db_session, User())

        assert user.is_active is True
        assert user.is_guest is False


class TestNoCredentialsOnUsers:
    async def test_users_table_has_no_provider_or_credential_columns(
        self, db_session: AsyncSession
    ) -> None:
        """D1: credentials live on user_identities only, never duplicated on users."""
        columns = await db_session.run_sync(
            lambda s: {c["name"] for c in inspect(s.connection()).get_columns("users")}
        )

        assert columns == {"id", "is_guest", "is_active", "created_at", "updated_at"}

    async def test_repr_has_no_pii(self, db_session: AsyncSession) -> None:
        user = await save(db_session, User())

        assert repr(user) == f"User(id={user.id!s}, is_guest=False)"
