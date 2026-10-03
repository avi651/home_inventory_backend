"""Sign in with Apple: authorization URL, ES256 client secret, code exchange, ID token checks.

The only module that talks to Apple; shared OIDC mechanics live in app.services.oidc.
Differences from Google, all required by Apple:

- The client secret is not a static string but a short-lived ES256 JWT we sign with the team's
  private key (.p8): kid=key id, iss=team id, sub=client id, aud=https://appleid.apple.com.
  A fresh one is minted for every code exchange, so it is never stored or reused.
- Requesting the `email` scope requires `response_mode=form_post`: Apple POSTs code/state to
  the redirect URI, which hands them to the client; the client then calls our /callback
  exactly as for Google. Anything else Apple posts there (`id_token`, `user`) is never trusted.
- `email_verified` arrives as a boolean or the string "true"/"false". Private-relay addresses
  (@privaterelay.appleid.com) are verified, per-app addresses and are stored like any other.
- PKCE is not in Apple's published parameter list. We still send an S256 challenge and the
  verifier (defence in depth), but security does not depend on Apple enforcing it: the
  attempt binding, single-use state and nonce do.

ID tokens are RS256 (Apple's JWKS publishes RSA keys); ES256 is only for our client secret.
"""

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from pydantic import SecretStr

from app.core.apple_keys import load_apple_private_key
from app.core.clock import Clock, utc_now
from app.core.config import Settings
from app.models.user_identity import IdentityProvider
from app.services.oidc import (
    DEFAULT_JWKS_CACHE_TTL,
    JwksCache,
    ProviderIdentity,
    decode_id_token,
    id_token_from_token_response,
    provider_request,
    standard_claims,
    verified_email,
)

APPLE_ISSUER = "https://appleid.apple.com"
APPLE_AUTHORIZATION_URL = "https://appleid.apple.com/auth/authorize"
APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"  # noqa: S105 - endpoint URL
APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys"
# Apple allows up to 6 months; minted per exchange, so minutes are plenty and limit exposure.
CLIENT_SECRET_LIFETIME = timedelta(minutes=5)
CLIENT_SECRET_ALGORITHM = "ES256"  # noqa: S105 - algorithm name, required by Apple
SCOPE = "email"


@dataclass(frozen=True)
class AppleOAuthConfig:
    team_id: str
    key_id: str
    client_id: str
    private_key: SecretStr = field(repr=False)
    redirect_uri: str

    @classmethod
    def from_settings(cls, settings: Settings) -> AppleOAuthConfig:
        if (
            settings.apple_team_id is None
            or settings.apple_key_id is None
            or settings.apple_client_id is None
            or settings.apple_private_key is None
            or settings.apple_redirect_uri is None
        ):
            raise ValueError("Sign in with Apple is not configured")
        return cls(
            team_id=settings.apple_team_id,
            key_id=settings.apple_key_id,
            client_id=settings.apple_client_id,
            private_key=settings.apple_private_key,
            redirect_uri=settings.apple_redirect_uri,
        )


class AppleOAuthClient:
    provider = IdentityProvider.APPLE

    def __init__(
        self,
        config: AppleOAuthConfig,
        http: httpx.AsyncClient,
        *,
        clock: Clock = utc_now,
        jwks_cache_ttl: timedelta = DEFAULT_JWKS_CACHE_TTL,
    ) -> None:
        self._config = config
        self._http = http
        self._clock = clock
        self._signing_key = load_apple_private_key(config.private_key.get_secret_value())
        self._jwks = JwksCache(http, APPLE_JWKS_URL, self.provider, clock=clock, ttl=jwks_cache_ttl)

    def __repr__(self) -> str:
        return f"AppleOAuthClient(client_id={self._config.client_id!r})"

    async def aclose(self) -> None:
        await self._http.aclose()

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        query = {
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "response_type": "code",
            "response_mode": "form_post",
            "scope": SCOPE,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{APPLE_AUTHORIZATION_URL}?{urlencode(query)}"

    def client_secret(self) -> str:
        """A fresh ES256 client-secret JWT for one token request."""
        now = self._clock().replace(microsecond=0)
        claims = {
            "iss": self._config.team_id,
            "sub": self._config.client_id,
            "aud": APPLE_ISSUER,
            "iat": int(now.timestamp()),
            "exp": int((now + CLIENT_SECRET_LIFETIME).timestamp()),
        }
        return jwt.encode(
            claims,
            self._signing_key,
            algorithm=CLIENT_SECRET_ALGORITHM,
            headers={"kid": self._config.key_id},
        )

    async def exchange_code(self, *, code: str, code_verifier: str) -> str:
        """Redeem the authorization code server-side; returns the raw ID token."""
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": self._config.client_id,
            "client_secret": self.client_secret(),
            "redirect_uri": self._config.redirect_uri,
        }
        response = await provider_request(
            self._http, self.provider, "POST", APPLE_TOKEN_URL, data=form
        )
        return id_token_from_token_response(response, self.provider)

    async def verify_id_token(self, id_token: str, *, nonce_hash: str) -> ProviderIdentity:
        """Signature (RS256, Apple JWKS), issuer, audience, time claims, nonce and subject."""
        claims = await decode_id_token(
            id_token, self._jwks, audience=self._config.client_id, issuer=APPLE_ISSUER
        )
        subject = standard_claims(
            claims, provider=self.provider, clock=self._clock, nonce_hash=nonce_hash
        )
        return ProviderIdentity(subject=subject, **_apple_email(claims))


def _apple_email(claims: dict[str, Any]) -> dict[str, Any]:
    # Apple documents email_verified as either a boolean or the string "true"/"false".
    flag = claims.get("email_verified")
    return verified_email(claims.get("email"), verified=flag is True or flag == "true")
