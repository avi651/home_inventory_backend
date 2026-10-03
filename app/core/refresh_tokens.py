"""Opaque refresh-token values. Never JWTs; only their SHA-256 hash is ever stored."""

import hashlib
import hmac
import re
import secrets

# Distinctive prefix: lets secret scanners (e.g. GitHub custom patterns) detect leaked tokens and
# lets the service reject garbage without a database round trip.
REFRESH_TOKEN_PREFIX = "hinv_rt_"  # noqa: S105 - public format prefix, not a secret
_TOKEN_BYTES = 32  # 256 bits of entropy
_WELL_FORMED = re.compile(rf"{REFRESH_TOKEN_PREFIX}[A-Za-z0-9_-]{{43}}")


def generate_refresh_token() -> str:
    return REFRESH_TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)


def is_well_formed(candidate: str) -> bool:
    return isinstance(candidate, str) and _WELL_FORMED.fullmatch(candidate) is not None


def hash_refresh_token(token: str) -> str:
    """SHA-256 hex. A pepper/KDF adds nothing for 256-bit random values: they cannot be guessed."""
    return hashlib.sha256(token.encode()).hexdigest()


def hashes_match(expected: str, actual: str) -> bool:
    return hmac.compare_digest(expected, actual)
