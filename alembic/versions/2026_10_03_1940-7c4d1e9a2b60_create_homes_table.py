"""create homes table

Revision ID: 7c4d1e9a2b60
Revises: 5b2e8c71d9a4
Create Date: 2026-10-03 19:40:00.000000

- FK user_id -> users.id ON DELETE CASCADE: a user's homes go with the user.
- UNIQUE (user_id, name_key): one name per user, case-insensitively; its leading user_id column
  also serves listing a user's homes and the FK cascade lookup (no separate user_id index).
- CHECKs: trimmed non-empty name, name_key is a SHA-256 hex digest, currency is 3 uppercase
  letters (the ISO 4217 allowlist itself is enforced in the application).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7c4d1e9a2b60"
down_revision: str | Sequence[str] | None = "5b2e8c71d9a4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "homes",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("name_key", sa.String(length=64), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
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
        sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name=op.f("ck_homes_currency_format")),
        sa.CheckConstraint(
            "char_length(name) >= 1 AND name = btrim(name)", name=op.f("ck_homes_name_trimmed")
        ),
        sa.CheckConstraint("name_key ~ '^[0-9a-f]{64}$'", name=op.f("ck_homes_name_key_format")),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_homes_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_homes")),
        sa.UniqueConstraint("user_id", "name_key", name="uq_homes_user_id_name_key"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("homes")
