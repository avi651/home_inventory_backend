"""A fake Google (authorization server + token endpoint + JWKS) behind httpx.MockTransport.

It behaves like the real one where it matters for security: codes are single-use, the PKCE
verifier must match the challenge sent on the authorization URL, and ID tokens are RS256-signed
with a key published on the JWKS endpoint.
"""

import base64
import hashlib
import json
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from functools import cache
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from app.services.google_oauth import (
    GOOGLE_JWKS_URL,
    GOOGLE_TOKEN_URL,
    GoogleOAuthClient,
    GoogleOAuthConfig,
)
from tests.support.clock import FrozenClock

CLIENT_ID = "test-client-id.apps.googleusercontent.com"
CLIENT_SECRET = "test-google-client-secret-Qw8zR2"
REDIRECT_URI = "https://app.example.com/oauth/google/callback"
KID = "test-key-1"


@cache
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@cache
def attacker_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {**jwk, "kid": kid, "alg": "RS256", "use": "sig"}


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass
class _Grant:
    nonce: str
    code_challenge: str


@dataclass
class FakeGoogle:
    clock: FrozenClock
    subject: str = "108234567890123456789"
    email: str | None = "gina@example.com"
    email_verified: bool = True
    # Per-test overrides of the ID token's claims/header, or of the token endpoint response.
    claim_overrides: dict[str, Any] = field(default_factory=dict)
    header_overrides: dict[str, Any] = field(default_factory=dict)
    sign_with: rsa.RSAPrivateKey | None = None
    token_response: Callable[[], httpx.Response] | None = None
    jwks_response: Callable[[], httpx.Response] | None = None
    token_requests: list[dict[str, str]] = field(default_factory=list)
    jwks_requests: int = 0
    _grants: dict[str, _Grant] = field(default_factory=dict)

    # --- the user's browser at Google ---------------------------------------------------
    def authorize(self, authorization_url: str) -> tuple[str, str]:
        """Approve the consent screen: returns (code, state) as Google's redirect carries."""
        query = {k: v[0] for k, v in parse_qs(urlsplit(authorization_url).query).items()}
        code = "4/0A" + secrets.token_urlsafe(40)
        self._grants[code] = _Grant(nonce=query["nonce"], code_challenge=query["code_challenge"])
        return code, query["state"]

    # --- tokens ---------------------------------------------------------------------------
    def id_token(self, nonce: str = "unused", **overrides: Any) -> str:
        now = int(self.clock().timestamp())
        claims: dict[str, Any] = {
            "iss": "https://accounts.google.com",
            "azp": CLIENT_ID,
            "aud": CLIENT_ID,
            "sub": self.subject,
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
        }
        if self.email is not None:
            claims["email"] = self.email
            claims["email_verified"] = self.email_verified
        claims.update(self.claim_overrides)
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not _ABSENT}
        headers = {"kid": KID, **self.header_overrides}
        return jwt.encode(
            claims, self.sign_with or signing_key(), algorithm="RS256", headers=headers
        )

    # --- HTTP endpoints -------------------------------------------------------------------
    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url == GOOGLE_JWKS_URL:
            self.jwks_requests += 1
            if self.jwks_response is not None:
                return self.jwks_response()
            return httpx.Response(200, json={"keys": [public_jwk(signing_key(), KID)]})
        if request.url == GOOGLE_TOKEN_URL and request.method == "POST":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(form)
            if self.token_response is not None:
                return self.token_response()
            return self._exchange(form)
        return httpx.Response(404)

    def _exchange(self, form: dict[str, str]) -> httpx.Response:
        invalid_grant = httpx.Response(400, json={"error": "invalid_grant"})
        if (
            form.get("grant_type") != "authorization_code"
            or form.get("client_id") != CLIENT_ID
            or form.get("client_secret") != CLIENT_SECRET
            or form.get("redirect_uri") != REDIRECT_URI
        ):
            return httpx.Response(401, json={"error": "invalid_client"})
        grant = self._grants.pop(form.get("code", ""), None)  # codes are single-use
        if grant is None or s256(form.get("code_verifier", "")) != grant.code_challenge:
            return invalid_grant
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.google-access-token-" + uuid.uuid4().hex,
                "expires_in": 3599,
                "id_token": self.id_token(nonce=grant.nonce),
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )

    # --- wiring ---------------------------------------------------------------------------
    def client(self, *, cache_ttl: timedelta | None = None) -> GoogleOAuthClient:
        config = GoogleOAuthConfig(
            client_id=CLIENT_ID,
            client_secret=SecretStr(CLIENT_SECRET),
            redirect_uri=REDIRECT_URI,
        )
        http = httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
        kwargs: dict[str, Any] = {} if cache_ttl is None else {"jwks_cache_ttl": cache_ttl}
        return GoogleOAuthClient(config, http, clock=self.clock, **kwargs)


_ABSENT: Any = object()
ABSENT = _ABSENT  # pass as a claim override to drop the claim entirely
