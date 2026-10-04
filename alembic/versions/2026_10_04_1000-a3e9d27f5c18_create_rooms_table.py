"""create rooms table

Revision ID: a3e9d27f5c18
Revises: 7c4d1e9a2b60
Create Date: 2026-10-04 10:00:00.000000

- No user_id: ownership is User -> Home -> Room (rooms.home_id -> homes.user_id).
- FK home_id -> homes.id ON DELETE CASCADE: a home's rooms go with the home (and so with the
  user, through the homes cascade).
- UNIQUE (home_id, name_key): one name per home, case-insensitively; its leading home_id column
  also serves listing a home's rooms and the FK cascade lookup (no separate home_id index).
- CHECKs: trimmed non-empty name, name_key is a SHA-256 hex digest.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3e9d27f5c18"
down_revision: str | Sequence[str] | None = "7c4d1e9a2b60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "rooms",
        sa.Column("home_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("name_key", sa.String(length=64), nullable=False),
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
            "char_length(name) >= 1 AND name = btrim(name)", name=op.f("ck_rooms_name_trimmed")
        ),
        sa.CheckConstraint("name_key ~ '^[0-9a-f]{64}$'", name=op.f("ck_rooms_name_key_format")),
        sa.ForeignKeyConstraint(
            ["home_id"], ["homes.id"], name=op.f("fk_rooms_home_id_homes"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rooms")),
        sa.UniqueConstraint("home_id", "name_key", name="uq_rooms_home_id_name_key"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("rooms")
