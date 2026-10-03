"""oauth_login_attempts: the database only ever holds digests of state, binding and nonce."""

import hashlib
import secrets
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_login_attempt import OAuthLoginAttempt
from app.models.user_identity import IdentityProvider

LATER = datetime(2030, 1, 1, tzinfo=UTC)


def digest() -> str:
    return hashlib.sha256(secrets.token_bytes(16)).hexdigest()


def attempt(**overrides: Any) -> OAuthLoginAttempt:
    values: dict[str, Any] = {
        "provider": IdentityProvider.GOOGLE,
        "state_hash": digest(),
        "binding_hash": digest(),
        "nonce_hash": digest(),
        "code_verifier": secrets.token_urlsafe(64),
        "expires_at": LATER,
    }
    values.update(overrides)
    return OAuthLoginAttempt(**values)


async def assert_rejected(db: AsyncSession, obj: OAuthLoginAttempt, constraint: str) -> None:
    db.add(obj)
    with pytest.raises(IntegrityError, match=constraint):
        await db.flush()
    await db.rollback()


async def test_valid_attempt_is_stored_with_uuid7(db_session: AsyncSession) -> None:
    row = attempt()
    db_session.add(row)
    await db_session.flush()

    assert row.id.version == 7


@pytest.mark.parametrize(
    ("field", "constraint"),
    [
        ("state_hash", "ck_oauth_login_attempts_state_hash_format"),
        ("binding_hash", "ck_oauth_login_attempts_binding_hash_format"),
        ("nonce_hash", "ck_oauth_login_attempts_nonce_hash_format"),
    ],
)
@pytest.mark.parametrize("value", ["raw-state-value", "A" * 64, "a" * 63])
async def test_only_sha256_hex_digests_can_be_stored(
    db_session: AsyncSession, field: str, constraint: str, value: str
) -> None:
    await assert_rejected(db_session, attempt(**{field: value}), constraint)


async def test_state_hash_is_unique(db_session: AsyncSession) -> None:
    state_hash = digest()
    db_session.add(attempt(state_hash=state_hash))
    await db_session.flush()

    await assert_rejected(
        db_session, attempt(state_hash=state_hash), "uq_oauth_login_attempts_state_hash"
    )


@pytest.mark.parametrize("verifier", ["short", "has space" + "x" * 40, "x" * 42])
async def test_code_verifier_must_be_rfc7636_shaped(
    db_session: AsyncSession, verifier: str
) -> None:
    await assert_rejected(
        db_session,
        attempt(code_verifier=verifier),
        "ck_oauth_login_attempts_code_verifier_format",
    )


async def test_code_verifier_is_at_most_128_chars(db_session: AsyncSession) -> None:
    db_session.add(attempt(code_verifier="x" * 129))

    with pytest.raises(DataError, match="too long"):
        await db_session.flush()
    await db_session.rollback()
