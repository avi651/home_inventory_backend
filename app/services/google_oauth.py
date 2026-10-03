"""Google OpenID Connect: authorization URL, server-side code exchange, ID token validation.

The only module that talks to Google; shared OIDC mechanics live in app.services.oidc. HTTP
goes through an injected httpx.AsyncClient so tests use a fake Google.
"""

from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
from pydantic import SecretStr

from app.core.clock import Clock, utc_now
from app.core.config import Settings
from app.models.user_identity import IdentityProvider
from app.services.oidc import (
    DEFAULT_JWKS_CACHE_TTL,
    JwksCache,
    ProviderIdentity,
    ProviderRejectedError,
    ProviderUnavailableError,
    decode_id_token,
    id_token_from_token_response,
    provider_request,
    standard_claims,
    verified_email,
)

__all__ = [
    "GOOGLE_AUTHORIZATION_URL",
    "GOOGLE_JWKS_URL",
    "GOOGLE_TOKEN_URL",
    "GoogleIdentity",
    "GoogleOAuthClient",
    "GoogleOAuthConfig",
    "ProviderRejectedError",
    "ProviderUnavailableError",
]

GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - endpoint URL
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
# Minimum scope: the stable `sub` plus the email for the "account already exists" check.
SCOPE = "openid email"

GoogleIdentity = ProviderIdentity


@dataclass(frozen=True)
class GoogleOAuthConfig:
    client_id: str
    client_secret: SecretStr
    redirect_uri: str

    @classmethod
    def from_settings(cls, settings: Settings) -> GoogleOAuthConfig:
        if (
            settings.google_client_id is None
            or settings.google_client_secret is None
            or settings.google_redirect_uri is None
        ):
            raise ValueError("Google OAuth is not configured")
        return cls(
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            redirect_uri=settings.google_redirect_uri,
        )


class GoogleOAuthClient:
    provider = IdentityProvider.GOOGLE

    def __init__(
        self,
        config: GoogleOAuthConfig,
        http: httpx.AsyncClient,
        *,
        clock: Clock = utc_now,
        jwks_cache_ttl: timedelta = DEFAULT_JWKS_CACHE_TTL,
    ) -> None:
        self._config = config
        self._http = http
        self._clock = clock
        self._jwks = JwksCache(
            http, GOOGLE_JWKS_URL, self.provider, clock=clock, ttl=jwks_cache_ttl
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        query = {
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "response_type": "code",
            "scope": SCOPE,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{GOOGLE_AUTHORIZATION_URL}?{urlencode(query)}"

    async def exchange_code(self, *, code: str, code_verifier: str) -> str:
        """Redeem the authorization code server-side; returns the raw ID token."""
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret.get_secret_value(),
            "redirect_uri": self._config.redirect_uri,
        }
        response = await provider_request(
            self._http, self.provider, "POST", GOOGLE_TOKEN_URL, data=form
        )
        return id_token_from_token_response(response, self.provider)

    async def verify_id_token(self, id_token: str, *, nonce_hash: str) -> ProviderIdentity:
        """Signature, issuer, audience, azp, time claims, nonce and subject."""
        claims = await decode_id_token(
            id_token, self._jwks, audience=self._config.client_id, issuer=GOOGLE_ISSUERS
        )
        subject = standard_claims(
            claims, provider=self.provider, clock=self._clock, nonce_hash=nonce_hash
        )
        azp = claims.get("azp")
        if azp is not None and azp != self._config.client_id:
            raise ProviderRejectedError("id token azp")
        return ProviderIdentity(subject=subject, **_google_email(claims))


def _google_email(claims: dict[str, Any]) -> dict[str, Any]:
    # Google sends email_verified as a JSON boolean; only literal true counts.
    return verified_email(claims.get("email"), verified=claims.get("email_verified") is True)
