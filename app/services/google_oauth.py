"""Google OpenID Connect: authorization URL, server-side code exchange, ID token validation.

The only module that talks to Google. HTTP goes through an injected httpx.AsyncClient so tests
use a fake Google. Errors are two opaque kinds -- rejected (bad code/token) and unavailable
(timeouts, 5xx, malformed answers) -- and never carry codes, tokens, secrets or provider
response bodies. Logs carry status codes and reasons only.
"""

import asyncio
import hashlib
import hmac
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from pydantic import SecretStr

from app.core.clock import Clock, utc_now
from app.core.config import Settings
from app.core.emails import InvalidEmailError, normalize_email
from app.models.user_identity import IdentityProvider
from app.services.identity_service import InvalidSubjectError, normalize_subject

logger = logging.getLogger(__name__)

GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - endpoint URL
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
# Minimum scope: the stable `sub` plus the email for the "account already exists" check.
SCOPE = "openid email"
HTTP_TIMEOUT = httpx.Timeout(5.0)
MAX_ID_TOKEN_LENGTH = 8192
# Tolerated clock skew between Google and us.
LEEWAY = timedelta(seconds=60)
DEFAULT_JWKS_CACHE_TTL = timedelta(hours=1)
# An unknown `kid` refetches the key set (rotation), but at most this often: forged tokens
# with random kids cannot turn us into a request amplifier against Google.
JWKS_MIN_REFETCH_INTERVAL = timedelta(seconds=60)
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


@dataclass(frozen=True)
class GoogleIdentity:
    """What we accept from Google: the stable subject, and an email only if Google verified it."""

    subject: str
    email: str | None
    email_verified: bool


class GoogleOAuthClient:
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
        self._jwks_cache_ttl = jwks_cache_ttl
        self._keys: dict[str, jwt.PyJWK] = {}
        self._keys_fetched_at: datetime | None = None
        self._jwks_lock = asyncio.Lock()

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
        response = await self._request("POST", GOOGLE_TOKEN_URL, data=form)
        if response.status_code == 429 or response.status_code >= 500:
            raise ProviderUnavailableError(f"token endpoint status {response.status_code}")
        if response.status_code != 200:
            # 400 invalid_grant: expired, replayed or PKCE-mismatched code; 401: client auth.
            logger.info("google code exchange rejected status=%d", response.status_code)
            raise ProviderRejectedError(f"token endpoint status {response.status_code}")
        id_token = _json_object(response).get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise ProviderUnavailableError("token response without id_token")
        return id_token

    async def verify_id_token(self, id_token: str, *, nonce_hash: str) -> GoogleIdentity:
        """Validate signature, issuer, audience, azp, time claims, nonce and subject.

        `nonce_hash` is the SHA-256 hex of the nonce sent on the authorization URL.
        """
        if not id_token or len(id_token) > MAX_ID_TOKEN_LENGTH:
            raise ProviderRejectedError("id token size")
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError:
            raise ProviderRejectedError("id token header") from None
        kid = header.get("kid")
        # RS256 only: rejects "none", HMAC (e.g. signed with the client secret) and alg mixups.
        if header.get("alg") != "RS256" or not isinstance(kid, str):
            raise ProviderRejectedError("id token algorithm")
        key = await self._signing_key(kid)
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key,
                algorithms=["RS256"],
                audience=self._config.client_id,
                issuer=GOOGLE_ISSUERS,
                options={
                    "require": ["iss", "aud", "sub", "iat", "exp", "nonce"],
                    "strict_aud": True,
                    # Time claims are checked below against the injectable clock.
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError:
            raise ProviderRejectedError("id token signature or claims") from None
        return self._identity(claims, nonce_hash)

    def _identity(self, claims: dict[str, Any], nonce_hash: str) -> GoogleIdentity:
        now = self._clock()
        expires_at, issued_at = _timestamp(claims["exp"]), _timestamp(claims["iat"])
        if expires_at < now - LEEWAY or issued_at > now + LEEWAY:
            raise ProviderRejectedError("id token time claims")
        azp = claims.get("azp")
        if azp is not None and azp != self._config.client_id:
            raise ProviderRejectedError("id token azp")
        nonce = claims["nonce"]
        if (
            not isinstance(nonce, str)
            or not _SHA256_HEX.fullmatch(nonce_hash)
            or not hmac.compare_digest(_sha256_hex(nonce), nonce_hash)
        ):
            raise ProviderRejectedError("id token nonce")
        subject = claims["sub"]
        if not isinstance(subject, str):
            raise ProviderRejectedError("id token subject")
        try:
            subject = normalize_subject(IdentityProvider.GOOGLE, subject)
        except InvalidSubjectError:
            raise ProviderRejectedError("id token subject") from None
        return GoogleIdentity(subject=subject, **_verified_email(claims))

    async def _signing_key(self, kid: str) -> jwt.PyJWK:
        async with self._jwks_lock:
            now = self._clock()
            fetched_at = self._keys_fetched_at
            stale = fetched_at is None or now - fetched_at >= self._jwks_cache_ttl
            may_refetch = fetched_at is None or now - fetched_at >= JWKS_MIN_REFETCH_INTERVAL
            if stale or (kid not in self._keys and may_refetch):
                self._keys = await self._fetch_keys()
                self._keys_fetched_at = now
            key = self._keys.get(kid)
        if key is None:
            raise ProviderRejectedError("id token unknown kid")
        return key

    async def _fetch_keys(self) -> dict[str, jwt.PyJWK]:
        response = await self._request("GET", GOOGLE_JWKS_URL)
        if response.status_code != 200:
            raise ProviderUnavailableError(f"jwks status {response.status_code}")
        try:
            key_set = jwt.PyJWKSet.from_dict(_json_object(response))
        except jwt.PyJWTError:
            raise ProviderUnavailableError("jwks malformed") from None
        return {key.key_id: key for key in key_set.keys if key.key_id}

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            return await self._http.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
        except httpx.TimeoutException:
            logger.warning("google request timed out endpoint=%s", _endpoint_name(url))
            raise ProviderUnavailableError("timeout") from None
        except httpx.HTTPError:
            logger.warning("google request failed endpoint=%s", _endpoint_name(url))
            raise ProviderUnavailableError("network error") from None


def _endpoint_name(url: str) -> str:
    return "jwks" if url == GOOGLE_JWKS_URL else "token"


def _json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        raise ProviderUnavailableError("non-json response") from None
    if not isinstance(body, dict):
        raise ProviderUnavailableError("non-object response")
    return body


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProviderRejectedError("id token time claims")
    try:
        return datetime.fromtimestamp(value, UTC)
    except OverflowError, OSError, ValueError:
        raise ProviderRejectedError("id token time claims") from None


def _verified_email(claims: dict[str, Any]) -> dict[str, Any]:
    """Only an address Google marks verified (literal JSON true) is kept, normalized.

    Unverified or unparseable addresses are dropped: the identity is keyed on `sub`, so the
    sign-in still works, and an unverified email can never trigger the account-exists check.
    """
    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str):
        return {"email": None, "email_verified": False}
    try:
        return {"email": normalize_email(email), "email_verified": True}
    except InvalidEmailError:
        return {"email": None, "email_verified": False}


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
