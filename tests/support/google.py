"""A fake Google behind httpx.MockTransport (see tests.support.oidc_fake)."""

from datetime import timedelta
from typing import Any, ClassVar

import httpx
from pydantic import SecretStr

from app.models.user_identity import IdentityProvider
from app.services.google_oauth import (
    GOOGLE_AUTHORIZATION_URL,
    GOOGLE_JWKS_URL,
    GOOGLE_TOKEN_URL,
    GoogleOAuthClient,
    GoogleOAuthConfig,
)
from tests.support.oidc_fake import (
    ABSENT,
    FakeOidcProvider,
    attacker_key,
    public_jwk,
    s256,
    signing_key,
)

__all__ = ["ABSENT", "FakeGoogle", "attacker_key", "public_jwk", "s256", "signing_key"]

CLIENT_ID = "test-client-id.apps.googleusercontent.com"
CLIENT_SECRET = "test-google-client-secret-Qw8zR2"
REDIRECT_URI = "https://app.example.com/oauth/google/callback"
KID = "test-key-1"


class FakeGoogle(FakeOidcProvider):
    provider: ClassVar[IdentityProvider] = IdentityProvider.GOOGLE
    ISSUER: ClassVar[str] = "https://accounts.google.com"
    CLIENT_ID: ClassVar[str] = CLIENT_ID
    REDIRECT_URI: ClassVar[str] = REDIRECT_URI
    AUTHORIZATION_URL: ClassVar[str] = GOOGLE_AUTHORIZATION_URL
    TOKEN_URL: ClassVar[str] = GOOGLE_TOKEN_URL
    JWKS_URL: ClassVar[str] = GOOGLE_JWKS_URL
    KID: ClassVar[str] = KID
    DEFAULT_SUBJECT: ClassVar[str] = "108234567890123456789"

    def extra_claims(self) -> dict[str, Any]:
        return {"azp": CLIENT_ID}

    def client_authenticated(self, form: dict[str, str]) -> bool:
        return form.get("client_secret") == CLIENT_SECRET

    def sensitive_values(self) -> list[str]:
        return [*super().sensitive_values(), CLIENT_SECRET]

    def client(self, *, cache_ttl: timedelta | None = None) -> GoogleOAuthClient:
        config = GoogleOAuthConfig(
            client_id=CLIENT_ID,
            client_secret=SecretStr(CLIENT_SECRET),
            redirect_uri=REDIRECT_URI,
        )
        http = httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
        kwargs: dict[str, Any] = {} if cache_ttl is None else {"jwks_cache_ttl": cache_ttl}
        return GoogleOAuthClient(config, http, clock=self.clock, **kwargs)
