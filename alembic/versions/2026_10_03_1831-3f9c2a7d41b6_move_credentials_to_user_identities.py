"""move credentials to user_identities (D1)

Revision ID: 3f9c2a7d41b6
Revises: 8bdc06075641
Create Date: 2026-10-03 18:31:48.392472

Each Phase 1 user holds at most one credential, so the upgrade copies it to exactly one
user_identities row (none for guests, who become users.is_guest) and then drops the old
columns. The whole migration runs in one transaction: any failure leaves the schema untouched.

The downgrade is reversible only while every user still fits the Phase 1 shape. It refuses,
rather than silently discarding data, if a user has linked more than one identity or if
an informational OAuth email would collide with another user's email.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3f9c2a7d41b6"
down_revision: str | Sequence[str] | None = "8bdc06075641"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PHASE1_PROVIDER_FIELDS = (
    "(auth_provider = 'email' AND email IS NOT NULL AND password_hash IS NOT NULL"
    " AND provider_subject IS NULL)"
    " OR (auth_provider IN ('google', 'apple') AND provider_subject IS NOT NULL"
    " AND provider_subject <> '' AND password_hash IS NULL)"
    " OR (auth_provider = 'guest' AND email IS NULL AND password_hash IS NULL"
    " AND provider_subject IS NULL)"
)


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "user_identities",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "provider",
            sa.Enum("email", "google", "apple", name="identity_provider"),
            nullable=False,
        ),
        sa.Column("subject", sa.String(length=320), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("email_verified", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("statement_timestamp()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("statement_timestamp()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(provider = 'email' AND email IS NOT NULL AND subject = email AND password_hash IS NOT NULL) OR (provider IN ('google', 'apple') AND subject <> '' AND password_hash IS NULL)",
            name=op.f("ck_user_identities_provider_fields"),
        ),
        sa.CheckConstraint(
            "position('@' in email) > 1", name=op.f("ck_user_identities_email_format")
        ),
        sa.CheckConstraint("email = lower(email)", name=op.f("ck_user_identities_email_lowercase")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_identities_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_identities")),
        sa.UniqueConstraint("provider", "subject", name="uq_user_identities_provider_subject"),
        sa.UniqueConstraint("user_id", "provider", name="uq_user_identities_user_id_provider"),
    )
    op.create_index(
        op.f("ix_user_identities_user_id"), "user_identities", ["user_id"], unique=False
    )
    op.add_column(
        "users",
        sa.Column("is_guest", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )

    # --- data: one identity per non-guest user; the old UNIQUEs guarantee no duplicates ---
    # PostgreSQL 17 has no uuidv7(): build one from a v4 by overwriting the first 48 bits with
    # the Unix-ms timestamp of the user's creation and setting the version nibble to 7 (RFC 9562).
    op.execute(
        "INSERT INTO user_identities"
        " (id, user_id, provider, subject, email, password_hash, created_at, updated_at)"
        " SELECT encode(set_bit(set_bit(overlay(uuid_send(gen_random_uuid()) placing"
        " substring(int8send(floor(extract(epoch FROM u.created_at) * 1000)::bigint) FROM 3)"
        " FROM 1 FOR 6), 52, 1), 53, 1), 'hex')::uuid,"
        " u.id, CAST(CAST(u.auth_provider AS text) AS identity_provider),"
        " CASE WHEN u.auth_provider = 'email' THEN u.email ELSE u.provider_subject END,"
        " u.email, u.password_hash, u.created_at, u.updated_at"
        " FROM users u WHERE u.auth_provider <> 'guest'"
    )
    op.execute("UPDATE users SET is_guest = true WHERE auth_provider = 'guest'")

    # Dropping the columns also drops the Phase 1 CHECK constraints that reference them.
    op.drop_constraint(op.f("uq_users_email"), "users", type_="unique")
    op.drop_constraint("uq_users_provider_subject", "users", type_="unique")
    op.drop_column("users", "provider_subject")
    op.drop_column("users", "auth_provider")
    op.drop_column("users", "email")
    op.drop_column("users", "password_hash")
    sa.Enum(name="auth_provider").drop(op.get_bind(), checkfirst=False)


def _refuse_lossy_downgrade() -> None:
    bind = op.get_bind()
    multi = bind.execute(
        sa.text(
            "SELECT count(*) FROM (SELECT 1 FROM user_identities GROUP BY user_id HAVING count(*) > 1) m"
        )
    ).scalar_one()
    if multi:
        raise RuntimeError(
            f"cannot downgrade: {multi} user(s) have more than one identity linked; "
            "the previous schema holds one credential per user"
        )
    collisions = bind.execute(
        sa.text(
            "SELECT count(*) FROM (SELECT email FROM user_identities WHERE email IS NOT NULL"
            " GROUP BY email HAVING count(*) > 1) c"
        )
    ).scalar_one()
    if collisions:
        raise RuntimeError(
            f"cannot downgrade: {collisions} email address(es) are shared by several users; "
            "the previous schema requires a globally unique email"
        )


def downgrade() -> None:
    """Downgrade schema."""
    _refuse_lossy_downgrade()

    auth_provider = sa.Enum("email", "google", "apple", "guest", name="auth_provider")
    auth_provider.create(op.get_bind(), checkfirst=False)
    op.add_column("users", sa.Column("password_hash", sa.String(length=255), nullable=True))
    op.add_column("users", sa.Column("email", sa.String(length=320), nullable=True))
    op.add_column("users", sa.Column("auth_provider", auth_provider, nullable=True))
    op.add_column("users", sa.Column("provider_subject", sa.String(length=255), nullable=True))

    op.execute(
        "UPDATE users u SET"
        " auth_provider = CAST(CAST(i.provider AS text) AS auth_provider),"
        " email = i.email, password_hash = i.password_hash,"
        " provider_subject = CASE WHEN i.provider = 'email' THEN NULL ELSE i.subject END"
        " FROM user_identities i WHERE i.user_id = u.id"
    )
    # Users without any identity (guests) map back to the Phase 1 guest provider.
    op.execute("UPDATE users SET auth_provider = 'guest' WHERE auth_provider IS NULL")
    op.alter_column("users", "auth_provider", nullable=False)

    op.create_check_constraint(
        op.f("ck_users_auth_provider_fields"), "users", _PHASE1_PROVIDER_FIELDS
    )
    op.create_check_constraint(op.f("ck_users_email_format"), "users", "position('@' in email) > 1")
    op.create_check_constraint(op.f("ck_users_email_lowercase"), "users", "email = lower(email)")
    op.create_unique_constraint(
        "uq_users_provider_subject", "users", ["auth_provider", "provider_subject"]
    )
    op.create_unique_constraint(op.f("uq_users_email"), "users", ["email"])

    op.drop_column("users", "is_guest")
    op.drop_index(op.f("ix_user_identities_user_id"), table_name="user_identities")
    op.drop_table("user_identities")
    # Alembic does not drop PostgreSQL enum types with their table.
    sa.Enum(name="identity_provider").drop(op.get_bind(), checkfirst=True)
