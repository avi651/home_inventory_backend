"""add oauth login attempts

Revision ID: 5b2e8c71d9a4
Revises: 3f9c2a7d41b6
Create Date: 2026-10-03 19:10:00.000000

Pending provider sign-ins (OAuth state) live in PostgreSQL so single use holds across workers.
Also indexes user_identities.email for the "email already has an account" check.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "5b2e8c71d9a4"
down_revision: str | Sequence[str] | None = "3f9c2a7d41b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "oauth_login_attempts",
        sa.Column(
            "provider",
            # Owned by the user_identities migration: reused, never created or dropped here.
            postgresql.ENUM(name="identity_provider", create_type=False),
            nullable=False,
        ),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("binding_hash", sa.String(length=64), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("code_verifier", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
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
            "binding_hash ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_oauth_login_attempts_binding_hash_format"),
        ),
        sa.CheckConstraint(
            "code_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'",
            name=op.f("ck_oauth_login_attempts_code_verifier_format"),
        ),
        sa.CheckConstraint(
            "nonce_hash ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_oauth_login_attempts_nonce_hash_format"),
        ),
        sa.CheckConstraint(
            "state_hash ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_oauth_login_attempts_state_hash_format"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth_login_attempts")),
        sa.UniqueConstraint("state_hash", name=op.f("uq_oauth_login_attempts_state_hash")),
    )
    op.create_index(
        op.f("ix_oauth_login_attempts_expires_at"),
        "oauth_login_attempts",
        ["expires_at"],
        unique=False,
    )
    op.create_index(op.f("ix_user_identities_email"), "user_identities", ["email"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_user_identities_email"), table_name="user_identities")
    op.drop_index(op.f("ix_oauth_login_attempts_expires_at"), table_name="oauth_login_attempts")
    op.drop_table("oauth_login_attempts")
