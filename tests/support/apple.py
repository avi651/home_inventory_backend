"""A fake Sign in with Apple behind httpx.MockTransport (see tests.support.oidc_fake).

Its token endpoint authenticates the client the way Apple does: `client_secret` must be an
ES256 JWT signed by the team's registered key (matching `kid`), with iss=team id,
sub=client id, aud=https://appleid.apple.com, and a current, at most 6-month validity.
"""

from datetime import timedelta
from functools import cache
from typing import Any, ClassVar

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr

from app.models.user_identity import IdentityProvider
from app.services.apple_oauth import (
    APPLE_AUTHORIZATION_URL,
    APPLE_ISSUER,
    APPLE_JWKS_URL,
    APPLE_TOKEN_URL,
    AppleOAuthClient,
    AppleOAuthConfig,
)
from tests.support.oidc_fake import FakeOidcProvider

TEAM_ID = "ABCDE12345"
KEY_ID = "KEY0123456"
CLIENT_ID = "com.example.homeinventory.signin"
REDIRECT_URI = "https://app.example.com/oauth/apple/callback"
KID = "apple-test-key-1"
MAX_CLIENT_SECRET_LIFETIME = timedelta(days=180)


@cache
def team_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@cache
def other_team_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def pem(key: Any) -> str:
    raw: bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return raw.decode()


def team_key_pem() -> str:
    return pem(team_key())


class FakeApple(FakeOidcProvider):
    provider: ClassVar[IdentityProvider] = IdentityProvider.APPLE
    ISSUER: ClassVar[str] = APPLE_ISSUER
    CLIENT_ID: ClassVar[str] = CLIENT_ID
    REDIRECT_URI: ClassVar[str] = REDIRECT_URI
    AUTHORIZATION_URL: ClassVar[str] = APPLE_AUTHORIZATION_URL
    TOKEN_URL: ClassVar[str] = APPLE_TOKEN_URL
    JWKS_URL: ClassVar[str] = APPLE_JWKS_URL
    KID: ClassVar[str] = KID
    DEFAULT_SUBJECT: ClassVar[str] = "001234.5f0c2b9d8e7a4c1b9f3e2d1c0b9a8f7e.1234"

    is_private_email: bool = False

    def extra_claims(self) -> dict[str, Any]:
        now = int(self.clock().timestamp())
        return {"auth_time": now, "nonce_supported": True}

    def email_claims(self) -> dict[str, Any]:
        if self.email is None:
            return {}
        # Apple sends these as strings ("true"/"false") as often as booleans.
        return {
            "email": self.email,
            "email_verified": "true" if self.email_verified else "false",
            "is_private_email": "true" if self.is_private_email else "false",
        }

    def client_secret_claims(self, secret: str) -> dict[str, Any] | None:
        """Apple's check of our client secret; None if Apple would reject it."""
        try:
            if jwt.get_unverified_header(secret).get("kid") != KEY_ID:
                return None
            claims: dict[str, Any] = jwt.decode(
                secret,
                team_key().public_key(),
                algorithms=["ES256"],
                audience=APPLE_ISSUER,
                issuer=TEAM_ID,
                options={
                    "require": ["iss", "iat", "exp", "aud", "sub"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError:
            return None
        now = int(self.clock().timestamp())
        lifetime = claims["exp"] - claims["iat"]
        if (
            claims["sub"] != CLIENT_ID
            or claims["exp"] <= now
            or claims["iat"] > now + 60
            or lifetime > MAX_CLIENT_SECRET_LIFETIME.total_seconds()
        ):
            return None
        return claims

    def client_authenticated(self, form: dict[str, str]) -> bool:
        return self.client_secret_claims(form.get("client_secret", "")) is not None

    def invalid_client(self) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_client"})

    def sensitive_values(self) -> list[str]:
        key_body = "".join(team_key_pem().splitlines()[1:-1])
        return [*super().sensitive_values(), key_body[:40], key_body[-40:]]

    def client(
        self,
        *,
        cache_ttl: timedelta | None = None,
        private_key_pem: str | None = None,
        key_id: str = KEY_ID,
    ) -> AppleOAuthClient:
        config = AppleOAuthConfig(
            team_id=TEAM_ID,
            key_id=key_id,
            client_id=CLIENT_ID,
            private_key=SecretStr(private_key_pem or team_key_pem()),
            redirect_uri=REDIRECT_URI,
        )
        http = httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
        kwargs: dict[str, Any] = {} if cache_ttl is None else {"jwks_cache_ttl": cache_ttl}
        return AppleOAuthClient(config, http, clock=self.clock, **kwargs)
