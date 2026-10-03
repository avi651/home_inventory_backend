import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from app.core.clock import Clock, utc_now
from app.core.config import Settings

ACCESS_TOKEN_TYPE = "access"  # noqa: S105 - token type label, not a credential
# Generous for our ~400-byte tokens; anything larger is rejected before any parsing work.
MAX_TOKEN_LENGTH = 4096
# Tolerated clock skew between token issuer and verifier.
LEEWAY = timedelta(seconds=5)
REQUIRED_CLAIMS = ("iss", "aud", "sub", "sid", "typ", "iat", "nbf", "exp", "jti")


class InvalidTokenError(Exception):
    """The single error for every token failure: callers and clients learn nothing about why."""

    def __init__(self) -> None:
        super().__init__("invalid token")


@dataclass(frozen=True)
class AccessTokenClaims:
    user_id: uuid.UUID
    session_id: uuid.UUID
    token_id: uuid.UUID
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class IssuedAccessToken:
    token: str
    expires_at: datetime
    expires_in: int  # seconds, for the OAuth-style token response


def _canonical_uuid(value: Any) -> uuid.UUID:
    """Only the exact form we issue (lowercase, hyphenated); uuid.UUID() alone is too lenient."""
    if not isinstance(value, str):
        raise InvalidTokenError
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise InvalidTokenError from None
    if str(parsed) != value:
        raise InvalidTokenError
    return parsed


def _timestamp(value: Any) -> datetime:
    # bool is an int subclass; floats allow "never expires" values like 1.5e30.
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidTokenError
    try:
        return datetime.fromtimestamp(value, UTC)
    except OverflowError, OSError, ValueError:
        raise InvalidTokenError from None


class AccessTokenService:
    """Issues and validates short-lived JWT access tokens."""

    def __init__(self, settings: Settings, clock: Clock = utc_now) -> None:
        self._key = settings.jwt_secret.get_secret_value()
        self._algorithm = settings.jwt_algorithm
        self._issuer = settings.jwt_issuer
        self._audience = settings.jwt_audience
        self._lifetime = timedelta(minutes=settings.access_token_expire_minutes)
        self._clock = clock

    def issue(self, *, user_id: uuid.UUID, session_id: uuid.UUID) -> IssuedAccessToken:
        now = self._clock().replace(microsecond=0)
        expires_at = now + self._lifetime
        claims = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": str(user_id),
            "sid": str(session_id),
            "typ": ACCESS_TOKEN_TYPE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(claims, self._key, algorithm=self._algorithm)
        return IssuedAccessToken(
            token=token,
            expires_at=expires_at,
            expires_in=int(self._lifetime.total_seconds()),
        )

    def decode(self, token: str) -> AccessTokenClaims:
        if not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH:
            raise InvalidTokenError
        try:
            payload = jwt.decode(
                token,
                self._key,
                # Exactly one algorithm: blocks "none", other HMAC sizes and RS/ES confusion.
                algorithms=[self._algorithm],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "require": list(REQUIRED_CLAIMS),
                    "strict_aud": True,
                    # Time claims are checked below against the injectable clock.
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError:
            raise InvalidTokenError from None
        return self._validate_claims(payload)

    def _validate_claims(self, payload: dict[str, Any]) -> AccessTokenClaims:
        if payload["typ"] != ACCESS_TOKEN_TYPE:
            raise InvalidTokenError

        issued_at = _timestamp(payload["iat"])
        not_before = _timestamp(payload["nbf"])
        expires_at = _timestamp(payload["exp"])
        now = self._clock()
        if expires_at < now - LEEWAY or not_before > now + LEEWAY or issued_at > now + LEEWAY:
            raise InvalidTokenError
        # Never honour a lifetime beyond the configured one: lowering the setting also caps
        # tokens already issued, and a minting bug cannot produce long-lived tokens.
        lifetime = expires_at - issued_at
        if lifetime <= timedelta(0) or lifetime > self._lifetime + LEEWAY:
            raise InvalidTokenError

        return AccessTokenClaims(
            user_id=_canonical_uuid(payload["sub"]),
            session_id=_canonical_uuid(payload["sid"]),
            token_id=_canonical_uuid(payload["jti"]),
            issued_at=issued_at,
            expires_at=expires_at,
        )
