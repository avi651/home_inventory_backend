"""Base for fake OIDC providers (authorization server + token endpoint + JWKS) on MockTransport.

Behaves like the real providers where it matters for security: codes are single-use, the PKCE
verifier must match the challenge sent on the authorization URL, and ID tokens are RS256-signed
with a key published on the JWKS endpoint. Subclasses add provider-specific claims and client
authentication.
"""

import base64
import hashlib
import json
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from app.models.user_identity import IdentityProvider
from app.services.oidc import OAuthProviderClient
from tests.support.clock import FrozenClock


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


_ABSENT: Any = object()
ABSENT = _ABSENT  # pass as a claim override to drop the claim entirely


@dataclass
class _Grant:
    nonce: str
    code_challenge: str


@dataclass
class FakeOidcProvider:
    provider: ClassVar[IdentityProvider]
    ISSUER: ClassVar[str]
    CLIENT_ID: ClassVar[str]
    REDIRECT_URI: ClassVar[str]
    AUTHORIZATION_URL: ClassVar[str]
    TOKEN_URL: ClassVar[str]
    JWKS_URL: ClassVar[str]
    KID: ClassVar[str]
    DEFAULT_SUBJECT: ClassVar[str]

    clock: FrozenClock
    subject: str = ""
    email: str | None = "gina@example.com"
    email_verified: bool = True
    # Per-test overrides of the ID token's claims/header, or of the endpoint responses.
    claim_overrides: dict[str, Any] = field(default_factory=dict)
    header_overrides: dict[str, Any] = field(default_factory=dict)
    sign_with: rsa.RSAPrivateKey | None = None
    token_response: Callable[[], httpx.Response] | None = None
    jwks_response: Callable[[], httpx.Response] | None = None
    token_requests: list[dict[str, str]] = field(default_factory=list)
    jwks_requests: int = 0
    _grants: dict[str, _Grant] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.subject = self.subject or self.DEFAULT_SUBJECT

    # --- the user's browser at the provider ------------------------------------------------
    def authorize(self, authorization_url: str) -> tuple[str, str]:
        """Approve the consent screen: returns (code, state) as the provider's redirect carries."""
        query = {k: v[0] for k, v in parse_qs(urlsplit(authorization_url).query).items()}
        code = "c" + secrets.token_urlsafe(40)
        self._grants[code] = _Grant(nonce=query["nonce"], code_challenge=query["code_challenge"])
        return code, query["state"]

    # --- tokens ---------------------------------------------------------------------------
    def extra_claims(self) -> dict[str, Any]:
        return {}

    def email_claims(self) -> dict[str, Any]:
        if self.email is None:
            return {}
        return {"email": self.email, "email_verified": self.email_verified}

    def id_token(self, nonce: str = "unused", **overrides: Any) -> str:
        now = int(self.clock().timestamp())
        claims: dict[str, Any] = {
            "iss": self.ISSUER,
            "aud": self.CLIENT_ID,
            "sub": self.subject,
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
            **self.extra_claims(),
            **self.email_claims(),
        }
        claims.update(self.claim_overrides)
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not _ABSENT}
        headers = {"kid": self.KID, **self.header_overrides}
        return jwt.encode(
            claims, self.sign_with or signing_key(), algorithm="RS256", headers=headers
        )

    # --- HTTP endpoints -------------------------------------------------------------------
    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url == self.JWKS_URL:
            self.jwks_requests += 1
            if self.jwks_response is not None:
                return self.jwks_response()
            return httpx.Response(200, json={"keys": [public_jwk(signing_key(), self.KID)]})
        if request.url == self.TOKEN_URL and request.method == "POST":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(form)
            if self.token_response is not None:
                return self.token_response()
            return self._exchange(form)
        return httpx.Response(404)

    def client_authenticated(self, form: dict[str, str]) -> bool:
        raise NotImplementedError

    def invalid_client(self) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    def _exchange(self, form: dict[str, str]) -> httpx.Response:
        if (
            form.get("grant_type") != "authorization_code"
            or form.get("client_id") != self.CLIENT_ID
            or form.get("redirect_uri") != self.REDIRECT_URI
            or not self.client_authenticated(form)
        ):
            return self.invalid_client()
        grant = self._grants.pop(form.get("code", ""), None)  # codes are single-use
        if grant is None or s256(form.get("code_verifier", "")) != grant.code_challenge:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(
            200,
            json={
                "access_token": "provider-access-token-" + uuid.uuid4().hex,
                "expires_in": 3599,
                "id_token": self.id_token(nonce=grant.nonce),
                "token_type": "Bearer",
                "refresh_token": "provider-refresh-token-" + uuid.uuid4().hex,
            },
        )

    def client(self) -> OAuthProviderClient:
        raise NotImplementedError

    # --- for assertions -------------------------------------------------------------------
    def sensitive_values(self) -> list[str]:
        """Values that must never appear in logs or API responses."""
        return [
            "provider-access-token-",
            "provider-refresh-token-",
            *(form.get("client_secret", "") for form in self.token_requests),
            *(form.get("code_verifier", "") for form in self.token_requests),
        ]
