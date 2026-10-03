"""GoogleOAuthClient: authorization URL, server-side code exchange and ID token validation."""

import base64
import hashlib
import json
import logging
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest

from app.services.google_oauth import (
    GOOGLE_AUTHORIZATION_URL,
    GoogleIdentity,
    GoogleOAuthClient,
    ProviderRejectedError,
    ProviderUnavailableError,
)
from tests.support.clock import FrozenClock
from tests.support.google import (
    ABSENT,
    CLIENT_ID,
    CLIENT_SECRET,
    KID,
    REDIRECT_URI,
    FakeGoogle,
    attacker_key,
    public_jwk,
    s256,
    signing_key,
)

NONCE = "n-0S6_WzA2Mj"
NONCE_HASH = hashlib.sha256(NONCE.encode()).hexdigest()


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def google(clock: FrozenClock) -> FakeGoogle:
    return FakeGoogle(clock=clock)


@pytest.fixture
def client(google: FakeGoogle) -> GoogleOAuthClient:
    return google.client()


async def verify(client: GoogleOAuthClient, token: str) -> GoogleIdentity:
    return await client.verify_id_token(token, nonce_hash=NONCE_HASH)


def unsigned_token() -> str:
    def b64(value: dict[str, Any]) -> str:
        raw = json.dumps(value).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    claims = {"sub": "x", "aud": CLIENT_ID, "iss": "https://accounts.google.com"}
    return f"{b64({'alg': 'none', 'kid': KID})}.{b64(claims)}."


def http_error(status: int, body: Any = None) -> httpx.Response:
    return httpx.Response(status, json=body if body is not None else {"error": "x"})


class TestAuthorizationUrl:
    def test_requests_code_flow_with_minimal_scope_state_nonce_and_pkce(
        self, client: GoogleOAuthClient
    ) -> None:
        url = client.authorization_url(state="st", nonce="no", code_challenge="ch")

        parts = urlsplit(url)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == GOOGLE_AUTHORIZATION_URL
        assert query == {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email",
            "state": "st",
            "nonce": "no",
            "code_challenge": "ch",
            "code_challenge_method": "S256",
        }

    def test_never_contains_the_client_secret(self, client: GoogleOAuthClient) -> None:
        url = client.authorization_url(state="st", nonce="no", code_challenge="ch")

        assert CLIENT_SECRET not in url


class TestCodeExchange:
    async def test_sends_code_verifier_and_client_credentials(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        verifier = "v" * 64
        url = client.authorization_url(state="st", nonce=NONCE, code_challenge=s256(verifier))
        code, _ = google.authorize(url)

        id_token = await client.exchange_code(code=code, code_verifier=verifier)

        assert (await verify(client, id_token)).subject == google.subject
        (sent,) = google.token_requests
        assert sent == {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
        }

    async def test_wrong_code_verifier_is_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        url = client.authorization_url(state="st", nonce=NONCE, code_challenge=s256("v" * 64))
        code, _ = google.authorize(url)

        with pytest.raises(ProviderRejectedError):
            await client.exchange_code(code=code, code_verifier="w" * 64)

    async def test_replayed_code_is_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        url = client.authorization_url(state="st", nonce=NONCE, code_challenge=s256("v" * 64))
        code, _ = google.authorize(url)
        await client.exchange_code(code=code, code_verifier="v" * 64)

        with pytest.raises(ProviderRejectedError):
            await client.exchange_code(code=code, code_verifier="v" * 64)

    @pytest.mark.parametrize("status", [400, 401, 403])
    async def test_client_errors_mean_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle, status: int
    ) -> None:
        google.token_response = lambda: http_error(status)

        with pytest.raises(ProviderRejectedError):
            await client.exchange_code(code="c", code_verifier="v" * 64)

    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    async def test_server_errors_mean_unavailable(
        self, client: GoogleOAuthClient, google: FakeGoogle, status: int
    ) -> None:
        google.token_response = lambda: http_error(status)

        with pytest.raises(ProviderUnavailableError):
            await client.exchange_code(code="c", code_verifier="v" * 64)

    @pytest.mark.parametrize(
        "exc", [httpx.ReadTimeout("slow"), httpx.ConnectTimeout("slow"), httpx.ConnectError("x")]
    )
    async def test_timeouts_and_network_errors_mean_unavailable(
        self, client: GoogleOAuthClient, google: FakeGoogle, exc: Exception
    ) -> None:
        def fail() -> httpx.Response:
            raise exc

        google.token_response = fail

        with pytest.raises(ProviderUnavailableError):
            await client.exchange_code(code="c", code_verifier="v" * 64)

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(200, content=b"<html>not json</html>"),
            httpx.Response(200, json=["not", "an", "object"]),
            httpx.Response(200, json={"access_token": "ya29.x"}),
            httpx.Response(200, json={"id_token": 12345}),
            httpx.Response(200, json={"id_token": ""}),
        ],
    )
    async def test_malformed_success_responses_mean_unavailable(
        self, client: GoogleOAuthClient, google: FakeGoogle, response: httpx.Response
    ) -> None:
        google.token_response = lambda: response

        with pytest.raises(ProviderUnavailableError):
            await client.exchange_code(code="c", code_verifier="v" * 64)

    async def test_errors_never_carry_provider_bodies_or_secrets(
        self,
        client: GoogleOAuthClient,
        google: FakeGoogle,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        google.token_response = lambda: http_error(
            400, {"error": "invalid_grant", "error_description": "provider-internal-detail"}
        )

        with pytest.raises(ProviderRejectedError) as exc_info:
            await client.exchange_code(code="secret-auth-code", code_verifier="v" * 64)

        text = str(exc_info.value) + repr(exc_info.value) + caplog.text
        for leaked in ("provider-internal-detail", "secret-auth-code", CLIENT_SECRET, "v" * 64):
            assert leaked not in text


class TestIdTokenValidation:
    async def test_valid_token_yields_sub_and_verified_email(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        identity = await verify(client, google.id_token(nonce=NONCE, email="Gina@Example.COM"))

        assert identity == GoogleIdentity(
            subject=google.subject, email="gina@example.com", email_verified=True
        )

    @pytest.mark.parametrize("issuer", ["https://accounts.google.com", "accounts.google.com"])
    async def test_both_documented_issuers_are_accepted(
        self, client: GoogleOAuthClient, google: FakeGoogle, issuer: str
    ) -> None:
        identity = await verify(client, google.id_token(nonce=NONCE, iss=issuer))

        assert identity.subject == google.subject

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"iss": "https://evil.example"}, id="wrong-issuer"),
            pytest.param({"iss": "https://accounts.google.com.evil.example"}, id="issuer-suffix"),
            pytest.param({"iss": ABSENT}, id="missing-issuer"),
            pytest.param({"aud": "someone-else.apps.googleusercontent.com"}, id="wrong-audience"),
            pytest.param({"aud": [CLIENT_ID, "other"]}, id="multi-audience"),
            pytest.param({"aud": ABSENT}, id="missing-audience"),
            pytest.param({"azp": "other-client"}, id="wrong-azp"),
            pytest.param({"sub": ABSENT}, id="missing-subject"),
            pytest.param({"sub": ""}, id="empty-subject"),
            pytest.param({"sub": 123456}, id="non-string-subject"),
            pytest.param({"sub": "a b"}, id="malformed-subject"),
            pytest.param({"nonce": "other-nonce"}, id="wrong-nonce"),
            pytest.param({"nonce": ABSENT}, id="missing-nonce"),
            pytest.param({"exp": ABSENT}, id="missing-exp"),
            pytest.param({"iat": ABSENT}, id="missing-iat"),
        ],
    )
    async def test_invalid_claims_are_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle, overrides: dict[str, Any]
    ) -> None:
        with pytest.raises(ProviderRejectedError):
            await verify(client, google.id_token(**{"nonce": NONCE, **overrides}))

    async def test_expired_token_is_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle, clock: FrozenClock
    ) -> None:
        token = google.id_token(nonce=NONCE)
        clock.advance(timedelta(hours=1, minutes=2))

        with pytest.raises(ProviderRejectedError):
            await verify(client, token)

    async def test_small_clock_skew_is_tolerated(
        self, client: GoogleOAuthClient, google: FakeGoogle, clock: FrozenClock
    ) -> None:
        token = google.id_token(nonce=NONCE)
        clock.advance(timedelta(hours=1, seconds=30))

        assert (await verify(client, token)).subject == google.subject

    async def test_token_issued_in_the_future_is_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle, clock: FrozenClock
    ) -> None:
        future = int((clock() + timedelta(minutes=10)).timestamp())

        with pytest.raises(ProviderRejectedError):
            await verify(client, google.id_token(nonce=NONCE, iat=future, exp=future + 3600))

    async def test_signature_from_another_key_is_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        google.sign_with = attacker_key()  # same kid, wrong key

        with pytest.raises(ProviderRejectedError):
            await verify(client, google.id_token(nonce=NONCE))

    async def test_tampered_payload_is_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        header, _, signature = google.id_token(nonce=NONCE).split(".")
        _, payload, _ = google.id_token(nonce=NONCE, sub="attacker-sub").split(".")
        google.sign_with = None

        with pytest.raises(ProviderRejectedError):
            await verify(client, f"{header}.{payload}.{signature}")

    @pytest.mark.parametrize(
        "token_factory",
        [
            pytest.param(
                lambda g: jwt.encode(
                    {"sub": "x", "aud": CLIENT_ID, "iss": "https://accounts.google.com"},
                    CLIENT_SECRET,
                    algorithm="HS256",
                    headers={"kid": "test-key-1"},
                ),
                id="hs256-with-client-secret",
            ),
            pytest.param(lambda g: unsigned_token(), id="alg-none"),
            pytest.param(lambda g: "not-a-jwt", id="garbage"),
            pytest.param(lambda g: "", id="empty"),
            pytest.param(lambda g: "a" * 20_000, id="oversized"),
        ],
    )
    async def test_forged_or_malformed_tokens_are_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle, token_factory: Any
    ) -> None:
        with pytest.raises(ProviderRejectedError):
            await verify(client, token_factory(google))

    @pytest.mark.parametrize("algorithm", ["RS512", "PS256"])
    async def test_other_algorithms_with_the_genuine_key_are_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle, algorithm: str
    ) -> None:
        """Only RS256: a valid signature under another algorithm is still refused."""
        claims = jwt.decode(google.id_token(nonce=NONCE), options={"verify_signature": False})
        token = jwt.encode(claims, signing_key(), algorithm=algorithm, headers={"kid": KID})

        with pytest.raises(ProviderRejectedError):
            await verify(client, token)

    async def test_unknown_kid_is_rejected(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        google.header_overrides = {"kid": "unknown-kid"}

        with pytest.raises(ProviderRejectedError):
            await verify(client, google.id_token(nonce=NONCE))

    async def test_unverified_email_is_not_returned(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        google.email_verified = False

        identity = await verify(client, google.id_token(nonce=NONCE))

        assert (identity.email, identity.email_verified) == (None, False)

    @pytest.mark.parametrize("verified", ["true", 1, ABSENT])
    async def test_only_boolean_true_counts_as_verified(
        self, client: GoogleOAuthClient, google: FakeGoogle, verified: Any
    ) -> None:
        identity = await verify(client, google.id_token(nonce=NONCE, email_verified=verified))

        assert identity.email is None

    async def test_missing_email_is_allowed(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        google.email = None

        identity = await verify(client, google.id_token(nonce=NONCE))

        assert identity == GoogleIdentity(subject=google.subject, email=None, email_verified=False)


class TestJwks:
    async def test_keys_are_cached(self, client: GoogleOAuthClient, google: FakeGoogle) -> None:
        for _ in range(3):
            await verify(client, google.id_token(nonce=NONCE))

        assert google.jwks_requests == 1

    async def test_cache_expires(self, google: FakeGoogle, clock: FrozenClock) -> None:
        client = google.client(cache_ttl=timedelta(minutes=5))
        await verify(client, google.id_token(nonce=NONCE))
        clock.advance(timedelta(minutes=6))

        await verify(client, google.id_token(nonce=NONCE))

        assert google.jwks_requests == 2

    async def test_rotated_key_triggers_one_refetch(
        self, client: GoogleOAuthClient, google: FakeGoogle, clock: FrozenClock
    ) -> None:
        await verify(client, google.id_token(nonce=NONCE))
        google.sign_with = attacker_key()
        google.header_overrides = {"kid": "rotated"}
        google.jwks_response = lambda: httpx.Response(
            200, json={"keys": [public_jwk(attacker_key(), "rotated")]}
        )
        clock.advance(timedelta(minutes=2))

        identity = await verify(client, google.id_token(nonce=NONCE))

        assert identity.subject == google.subject
        assert google.jwks_requests == 2

    async def test_unknown_kids_cannot_force_repeated_refetches(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        await verify(client, google.id_token(nonce=NONCE))
        google.header_overrides = {"kid": "unknown"}

        for _ in range(5):
            with pytest.raises(ProviderRejectedError):
                await verify(client, google.id_token(nonce=NONCE))

        assert google.jwks_requests <= 2

    @pytest.mark.parametrize(
        "response",
        [
            lambda: httpx.Response(500),
            lambda: httpx.Response(200, content=b"nope"),
            lambda: httpx.Response(200, json={"keys": "nope"}),
        ],
    )
    async def test_jwks_failures_mean_unavailable(
        self, client: GoogleOAuthClient, google: FakeGoogle, response: Any
    ) -> None:
        google.jwks_response = response

        with pytest.raises(ProviderUnavailableError):
            await verify(client, google.id_token(nonce=NONCE))

    async def test_jwks_timeout_means_unavailable(
        self, client: GoogleOAuthClient, google: FakeGoogle
    ) -> None:
        def fail() -> httpx.Response:
            raise httpx.ReadTimeout("slow")

        google.jwks_response = fail

        with pytest.raises(ProviderUnavailableError):
            await verify(client, google.id_token(nonce=NONCE))
