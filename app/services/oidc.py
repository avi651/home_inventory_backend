"""Building blocks shared by OpenID Connect sign-in providers (Google, Apple).

Errors are two opaque kinds -- rejected (bad code/token) and unavailable (timeouts, 5xx,
malformed answers) -- and never carry codes, tokens, secrets or provider response bodies.
Logs carry provider names, status codes and fixed reasons only.
"""

import asyncio
import hashlib
import hmac
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx
import jwt

from app.core.clock import Clock
from app.core.emails import InvalidEmailError, normalize_email
from app.models.user_identity import IdentityProvider
from app.services.identity_service import InvalidSubjectError, normalize_subject

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = httpx.Timeout(5.0)
MAX_ID_TOKEN_LENGTH = 8192
# Tolerated clock skew between the provider and us.
LEEWAY = timedelta(seconds=60)
DEFAULT_JWKS_CACHE_TTL = timedelta(hours=1)
# An unknown `kid` refetches the key set (rotation), but at most this often: forged tokens
# with random kids cannot turn us into a request amplifier against the provider.
JWKS_MIN_REFETCH_INTERVAL = timedelta(seconds=60)
# Both Google and Apple sign ID tokens with RS256. Anything else ("none", HMAC keyed with a
# client secret, ES256, RS512, PS256, ...) is refused before and during verification.
ID_TOKEN_ALGORITHM = "RS256"  # noqa: S105 - algorithm name, not a secret
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class ProviderRejectedError(Exception):
    """The provider (or its signed token) did not vouch for this sign-in."""

    def __init__(self, reason: str) -> None:
        super().__init__("provider rejected the sign-in")
        self.reason = reason  # fixed internal label for logs, never provider-supplied text


class ProviderUnavailableError(Exception):
    """Timeout, network failure, 429/5xx or a malformed provider response."""

    def __init__(self, reason: str) -> None:
        super().__init__("provider unavailable")
        self.reason = reason


@dataclass(frozen=True)
class ProviderIdentity:
    """What we accept from a provider: the stable subject, and an email only if verified."""

    subject: str
    email: str | None
    email_verified: bool


class OAuthProviderClient(Protocol):
    """One OIDC provider as OAuthSignInService needs it."""

    @property
    def provider(self) -> IdentityProvider: ...

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str: ...

    async def exchange_code(self, *, code: str, code_verifier: str) -> str: ...

    async def verify_id_token(self, id_token: str, *, nonce_hash: str) -> ProviderIdentity: ...

    async def aclose(self) -> None: ...


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def provider_request(
    http: httpx.AsyncClient, provider: IdentityProvider, method: str, url: str, **kwargs: Any
) -> httpx.Response:
    try:
        return await http.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
    except httpx.TimeoutException:
        logger.warning("%s request timed out", provider.value)
        raise ProviderUnavailableError("timeout") from None
    except httpx.HTTPError:
        logger.warning("%s request failed", provider.value)
        raise ProviderUnavailableError("network error") from None


def json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        raise ProviderUnavailableError("non-json response") from None
    if not isinstance(body, dict):
        raise ProviderUnavailableError("non-object response")
    return body


def id_token_from_token_response(response: httpx.Response, provider: IdentityProvider) -> str:
    """Map a token-endpoint answer to the raw ID token, or to one of the two opaque errors."""
    if response.status_code == 429 or response.status_code >= 500:
        raise ProviderUnavailableError(f"token endpoint status {response.status_code}")
    if response.status_code != 200:
        # 400 invalid_grant: expired, replayed or PKCE-mismatched code; invalid_client etc.
        logger.info("%s code exchange rejected status=%d", provider.value, response.status_code)
        raise ProviderRejectedError(f"token endpoint status {response.status_code}")
    id_token = json_object(response).get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise ProviderUnavailableError("token response without id_token")
    return id_token


class JwksCache:
    """The provider's signing keys by `kid`: cached, refreshed on expiry or (throttled) rotation."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        url: str,
        provider: IdentityProvider,
        *,
        clock: Clock,
        ttl: timedelta = DEFAULT_JWKS_CACHE_TTL,
    ) -> None:
        self._http = http
        self._url = url
        self._provider = provider
        self._clock = clock
        self._ttl = ttl
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: datetime | None = None
        self._lock = asyncio.Lock()

    async def key(self, kid: str) -> jwt.PyJWK:
        async with self._lock:
            now = self._clock()
            fetched_at = self._fetched_at
            stale = fetched_at is None or now - fetched_at >= self._ttl
            may_refetch = fetched_at is None or now - fetched_at >= JWKS_MIN_REFETCH_INTERVAL
            if stale or (kid not in self._keys and may_refetch):
                self._keys = await self._fetch()
                self._fetched_at = now
            key = self._keys.get(kid)
        if key is None:
            raise ProviderRejectedError("id token unknown kid")
        return key

    async def _fetch(self) -> dict[str, jwt.PyJWK]:
        response = await provider_request(self._http, self._provider, "GET", self._url)
        if response.status_code != 200:
            raise ProviderUnavailableError(f"jwks status {response.status_code}")
        try:
            key_set = jwt.PyJWKSet.from_dict(json_object(response))
        except jwt.PyJWTError:
            raise ProviderUnavailableError("jwks malformed") from None
        return {key.key_id: key for key in key_set.keys if key.key_id}


async def decode_id_token(
    id_token: str,
    jwks: JwksCache,
    *,
    audience: str,
    issuer: str | tuple[str, ...],
) -> dict[str, Any]:
    """Signature (RS256 key from the provider's JWKS), issuer, audience and required claims.

    Time claims, nonce and subject are checked by `standard_claims` against our clock.
    """
    if not id_token or len(id_token) > MAX_ID_TOKEN_LENGTH:
        raise ProviderRejectedError("id token size")
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise ProviderRejectedError("id token header") from None
    kid = header.get("kid")
    if header.get("alg") != ID_TOKEN_ALGORITHM or not isinstance(kid, str):
        raise ProviderRejectedError("id token algorithm")
    key = await jwks.key(kid)
    try:
        claims: dict[str, Any] = jwt.decode(
            id_token,
            key,
            algorithms=[ID_TOKEN_ALGORITHM],
            audience=audience,
            issuer=issuer,
            options={
                "require": ["iss", "aud", "sub", "iat", "exp", "nonce"],
                "strict_aud": True,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError:
        raise ProviderRejectedError("id token signature or claims") from None
    return claims


def standard_claims(
    claims: dict[str, Any], *, provider: IdentityProvider, clock: Clock, nonce_hash: str
) -> str:
    """Check exp/iat (with leeway) and the nonce; return the validated, canonical subject.

    `nonce_hash` is the SHA-256 hex of the nonce sent on the authorization URL.
    """
    now = clock()
    expires_at, issued_at = _timestamp(claims["exp"]), _timestamp(claims["iat"])
    if expires_at < now - LEEWAY or issued_at > now + LEEWAY:
        raise ProviderRejectedError("id token time claims")
    nonce = claims["nonce"]
    if (
        not isinstance(nonce, str)
        or not _SHA256_HEX.fullmatch(nonce_hash)
        or not hmac.compare_digest(sha256_hex(nonce), nonce_hash)
    ):
        raise ProviderRejectedError("id token nonce")
    subject = claims["sub"]
    if not isinstance(subject, str):
        raise ProviderRejectedError("id token subject")
    try:
        return normalize_subject(provider, subject)
    except InvalidSubjectError:
        raise ProviderRejectedError("id token subject") from None


def verified_email(email: Any, *, verified: bool) -> dict[str, Any]:
    """Keep an address only if the provider verified it, normalized; otherwise drop it.

    The identity is keyed on `sub`, so the sign-in still works without an email, and an
    unverified address can never trigger the account-exists check.
    """
    if not verified or not isinstance(email, str):
        return {"email": None, "email_verified": False}
    try:
        return {"email": normalize_email(email), "email_verified": True}
    except InvalidEmailError:
        return {"email": None, "email_verified": False}


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProviderRejectedError("id token time claims")
    try:
        return datetime.fromtimestamp(value, UTC)
    except OverflowError, OSError, ValueError:
        raise ProviderRejectedError("id token time claims") from None
