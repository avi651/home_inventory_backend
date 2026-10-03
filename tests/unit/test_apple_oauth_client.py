"""AppleOAuthClient: authorization URL, ES256 client secret, code exchange, ID token validation."""

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
from cryptography.hazmat.primitives.asymmetric import ec

from app.services.apple_oauth import (
    APPLE_AUTHORIZATION_URL,
    APPLE_ISSUER,
    CLIENT_SECRET_LIFETIME,
    AppleOAuthClient,
)
from app.services.oidc import ProviderIdentity, ProviderRejectedError, ProviderUnavailableError
from tests.support.apple import (
    CLIENT_ID,
    KEY_ID,
    KID,
    REDIRECT_URI,
    TEAM_ID,
    FakeApple,
    other_team_key,
    pem,
    team_key,
    team_key_pem,
)
from tests.support.clock import FrozenClock
from tests.support.oidc_fake import ABSENT, attacker_key, public_jwk, s256, signing_key

NONCE = "n-0S6_WzA2Mj-apple"
NONCE_HASH = hashlib.sha256(NONCE.encode()).hexdigest()
VERIFIER = "v" * 64


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def apple(clock: FrozenClock) -> FakeApple:
    return FakeApple(clock=clock)


@pytest.fixture
def client(apple: FakeApple) -> AppleOAuthClient:
    return apple.client()


async def verify(client: AppleOAuthClient, token: str) -> ProviderIdentity:
    return await client.verify_id_token(token, nonce_hash=NONCE_HASH)


async def redeem(client: AppleOAuthClient, apple: FakeApple) -> str:
    url = client.authorization_url(state="st", nonce=NONCE, code_challenge=s256(VERIFIER))
    code, _ = apple.authorize(url)
    return await client.exchange_code(code=code, code_verifier=VERIFIER)


def unsigned_token(**claims: Any) -> str:
    def b64(value: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none', 'kid': KID})}.{b64(claims)}."


class TestAuthorizationUrl:
    def test_code_flow_with_form_post_email_scope_state_nonce_and_pkce(
        self, client: AppleOAuthClient
    ) -> None:
        url = client.authorization_url(state="st", nonce="no", code_challenge="ch")

        parts = urlsplit(url)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == APPLE_AUTHORIZATION_URL
        assert query == {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            # Apple requires form_post whenever a scope is requested.
            "response_mode": "form_post",
            "scope": "email",
            "state": "st",
            "nonce": "no",
            "code_challenge": "ch",
            "code_challenge_method": "S256",
        }

    def test_never_contains_key_material(self, client: AppleOAuthClient) -> None:
        url = client.authorization_url(state="st", nonce="no", code_challenge="ch")

        assert "client_secret" not in url
        assert KEY_ID not in url
        assert TEAM_ID not in url


class TestClientSecret:
    def test_is_an_es256_jwt_with_apples_required_claims(
        self, client: AppleOAuthClient, clock: FrozenClock
    ) -> None:
        secret = client.client_secret()

        header = jwt.get_unverified_header(secret)
        assert header == {"alg": "ES256", "kid": KEY_ID, "typ": "JWT"}
        claims = jwt.decode(
            secret,
            team_key().public_key(),
            algorithms=["ES256"],
            audience=APPLE_ISSUER,
            options={"verify_exp": False, "verify_iat": False},
        )
        now = int(clock().timestamp())
        assert claims == {
            "iss": TEAM_ID,
            "sub": CLIENT_ID,
            "aud": "https://appleid.apple.com",
            "iat": now,
            "exp": now + int(CLIENT_SECRET_LIFETIME.total_seconds()),
        }

    def test_lifetime_is_short_and_within_apples_six_month_cap(self) -> None:
        assert timedelta(0) < CLIENT_SECRET_LIFETIME <= timedelta(minutes=10)

    def test_apple_accepts_it(self, client: AppleOAuthClient, apple: FakeApple) -> None:
        assert apple.client_secret_claims(client.client_secret()) is not None

    def test_expired_secret_is_rejected(
        self, client: AppleOAuthClient, apple: FakeApple, clock: FrozenClock
    ) -> None:
        secret = client.client_secret()
        clock.advance(CLIENT_SECRET_LIFETIME + timedelta(seconds=1))

        assert apple.client_secret_claims(secret) is None

    async def test_a_fresh_secret_is_minted_for_every_exchange(
        self, client: AppleOAuthClient, apple: FakeApple, clock: FrozenClock
    ) -> None:
        await redeem(client, apple)
        clock.advance(timedelta(days=200))

        assert await redeem(client, apple)

    async def test_secret_signed_with_the_wrong_key_is_rejected(self, apple: FakeApple) -> None:
        client = apple.client(private_key_pem=pem(other_team_key()))

        with pytest.raises(ProviderRejectedError):
            await redeem(client, apple)

    async def test_secret_with_the_wrong_key_id_is_rejected(self, apple: FakeApple) -> None:
        client = apple.client(key_id="WRONG01234")

        with pytest.raises(ProviderRejectedError):
            await redeem(client, apple)

    @pytest.mark.parametrize("algorithm", ["ES384", "HS256"])
    def test_apple_rejects_other_algorithms(self, apple: FakeApple, algorithm: str) -> None:
        """Documents the contract our ES256 secret must meet."""
        key: Any = ec.generate_private_key(ec.SECP384R1()) if algorithm == "ES384" else "x" * 32
        claims = {"iss": TEAM_ID, "sub": CLIENT_ID, "aud": APPLE_ISSUER, "iat": 1, "exp": 2}
        forged = jwt.encode(claims, key, algorithm=algorithm, headers={"kid": KEY_ID})

        assert apple.client_secret_claims(forged) is None

    def test_key_material_never_appears_in_reprs(self, client: AppleOAuthClient) -> None:
        body = "".join(team_key_pem().splitlines()[1:-1])

        for text in (repr(client), repr(client._config), str(vars(client))):
            assert body[:40] not in text
            assert "PRIVATE KEY" not in text

    async def test_private_key_and_secret_are_never_logged_or_raised(
        self, client: AppleOAuthClient, apple: FakeApple, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        apple.token_response = lambda: httpx.Response(
            400, json={"error": "invalid_client", "detail": "apple-internal-detail"}
        )

        with pytest.raises(ProviderRejectedError) as exc_info:
            await client.exchange_code(code="secret-auth-code", code_verifier=VERIFIER)

        text = caplog.text + str(exc_info.value) + repr(exc_info.value)
        (sent,) = apple.token_requests
        for leaked in (
            *apple.sensitive_values(),
            sent["client_secret"],
            "secret-auth-code",
            VERIFIER,
            "apple-internal-detail",
            "PRIVATE KEY",
        ):
            assert leaked not in text


class TestKeyNeverLogged:
    async def test_whole_client_lifecycle_never_logs_key_material(
        self, apple: FakeApple, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Captures from before construction: loading the key must not log it either."""
        caplog.set_level(logging.DEBUG)

        client = apple.client()
        await verify_flow(client, apple)
        await client.aclose()

        body = "".join(team_key_pem().splitlines()[1:-1])
        logged = caplog.text
        for leaked in (body[:40], body[-40:], "PRIVATE KEY", *apple.sensitive_values()):
            assert leaked not in logged


async def verify_flow(client: AppleOAuthClient, apple: FakeApple) -> None:
    url = client.authorization_url(state="st", nonce=NONCE, code_challenge=s256(VERIFIER))
    code, _ = apple.authorize(url)
    id_token = await client.exchange_code(code=code, code_verifier=VERIFIER)
    await verify(client, id_token)


class TestCodeExchange:
    async def test_sends_code_verifier_and_client_secret_jwt(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        id_token = await redeem(client, apple)

        assert (await verify(client, id_token)).subject == apple.subject
        (sent,) = apple.token_requests
        assert set(sent) == {
            "grant_type",
            "code",
            "code_verifier",
            "client_id",
            "client_secret",
            "redirect_uri",
        }
        assert (sent["grant_type"], sent["client_id"], sent["redirect_uri"]) == (
            "authorization_code",
            CLIENT_ID,
            REDIRECT_URI,
        )
        assert sent["code_verifier"] == VERIFIER
        assert apple.client_secret_claims(sent["client_secret"]) is not None

    async def test_wrong_code_verifier_is_rejected(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        url = client.authorization_url(state="st", nonce=NONCE, code_challenge=s256(VERIFIER))
        code, _ = apple.authorize(url)

        with pytest.raises(ProviderRejectedError):
            await client.exchange_code(code=code, code_verifier="w" * 64)

    async def test_missing_code_verifier_is_rejected(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        url = client.authorization_url(state="st", nonce=NONCE, code_challenge=s256(VERIFIER))
        code, _ = apple.authorize(url)

        with pytest.raises(ProviderRejectedError):
            await client.exchange_code(code=code, code_verifier="")

    async def test_invalid_and_replayed_codes_are_rejected(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        url = client.authorization_url(state="st", nonce=NONCE, code_challenge=s256(VERIFIER))
        code, _ = apple.authorize(url)
        await client.exchange_code(code=code, code_verifier=VERIFIER)

        with pytest.raises(ProviderRejectedError):
            await client.exchange_code(code=code, code_verifier=VERIFIER)
        with pytest.raises(ProviderRejectedError):
            await client.exchange_code(code="never-issued", code_verifier=VERIFIER)

    @pytest.mark.parametrize("status", [400, 401, 403])
    async def test_client_errors_mean_rejected(
        self, client: AppleOAuthClient, apple: FakeApple, status: int
    ) -> None:
        apple.token_response = lambda: httpx.Response(status, json={"error": "x"})

        with pytest.raises(ProviderRejectedError):
            await client.exchange_code(code="c", code_verifier=VERIFIER)

    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    async def test_server_errors_mean_unavailable(
        self, client: AppleOAuthClient, apple: FakeApple, status: int
    ) -> None:
        apple.token_response = lambda: httpx.Response(status)

        with pytest.raises(ProviderUnavailableError):
            await client.exchange_code(code="c", code_verifier=VERIFIER)

    @pytest.mark.parametrize(
        "exc", [httpx.ReadTimeout("slow"), httpx.ConnectTimeout("slow"), httpx.ConnectError("x")]
    )
    async def test_timeouts_and_connection_failures_mean_unavailable(
        self, client: AppleOAuthClient, apple: FakeApple, exc: Exception
    ) -> None:
        def fail() -> httpx.Response:
            raise exc

        apple.token_response = fail

        with pytest.raises(ProviderUnavailableError):
            await client.exchange_code(code="c", code_verifier=VERIFIER)

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(200, content=b"<html>not json</html>"),
            httpx.Response(200, json=["not", "an", "object"]),
            httpx.Response(200, json={"access_token": "a", "token_type": "Bearer"}),
            httpx.Response(200, json={"id_token": None}),
            httpx.Response(200, json={"id_token": ""}),
        ],
    )
    async def test_invalid_token_responses_mean_unavailable(
        self, client: AppleOAuthClient, apple: FakeApple, response: httpx.Response
    ) -> None:
        apple.token_response = lambda: response

        with pytest.raises(ProviderUnavailableError):
            await client.exchange_code(code="c", code_verifier=VERIFIER)

    async def test_malformed_id_token_in_a_success_response_is_rejected(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        apple.token_response = lambda: httpx.Response(200, json={"id_token": "not.a.jwt"})

        id_token = await client.exchange_code(code="c", code_verifier=VERIFIER)

        with pytest.raises(ProviderRejectedError):
            await verify(client, id_token)


class TestIdTokenValidation:
    async def test_valid_token_yields_sub_and_verified_email(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        identity = await verify(client, apple.id_token(nonce=NONCE, email="Gina@Example.COM"))

        assert identity == ProviderIdentity(
            subject=apple.subject, email="gina@example.com", email_verified=True
        )

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"iss": "https://appleid.apple.com.evil.example"}, id="issuer-suffix"),
            pytest.param({"iss": "https://accounts.google.com"}, id="google-issuer"),
            pytest.param({"iss": "appleid.apple.com"}, id="schemeless-issuer"),
            pytest.param({"iss": ABSENT}, id="missing-issuer"),
            pytest.param({"aud": "com.example.other"}, id="wrong-audience"),
            pytest.param({"aud": [CLIENT_ID, "other"]}, id="multi-audience"),
            pytest.param({"aud": ABSENT}, id="missing-audience"),
            pytest.param({"sub": ABSENT}, id="missing-subject"),
            pytest.param({"sub": ""}, id="empty-subject"),
            pytest.param({"sub": 1234}, id="non-string-subject"),
            pytest.param({"sub": "001234.abc def"}, id="malformed-subject"),
            pytest.param({"sub": "x" * 300}, id="overlong-subject"),
            pytest.param({"nonce": "other-nonce"}, id="wrong-nonce"),
            pytest.param({"nonce": ABSENT}, id="missing-nonce"),
            pytest.param({"nonce": 12345}, id="malformed-nonce"),
            pytest.param({"nonce": hashlib.sha256(NONCE.encode()).hexdigest()}, id="hashed-nonce"),
            pytest.param({"exp": ABSENT}, id="missing-exp"),
            pytest.param({"iat": ABSENT}, id="missing-iat"),
            pytest.param({"exp": "9999999999"}, id="string-exp"),
        ],
    )
    async def test_invalid_claims_are_rejected(
        self, client: AppleOAuthClient, apple: FakeApple, overrides: dict[str, Any]
    ) -> None:
        with pytest.raises(ProviderRejectedError):
            await verify(client, apple.id_token(**{"nonce": NONCE, **overrides}))

    async def test_expired_token_is_rejected(
        self, client: AppleOAuthClient, apple: FakeApple, clock: FrozenClock
    ) -> None:
        token = apple.id_token(nonce=NONCE)
        clock.advance(timedelta(hours=1, minutes=2))

        with pytest.raises(ProviderRejectedError):
            await verify(client, token)

    async def test_token_issued_in_the_future_is_rejected(
        self, client: AppleOAuthClient, apple: FakeApple, clock: FrozenClock
    ) -> None:
        future = int((clock() + timedelta(minutes=10)).timestamp())

        with pytest.raises(ProviderRejectedError):
            await verify(client, apple.id_token(nonce=NONCE, iat=future, exp=future + 3600))

    async def test_wrong_signing_key_is_rejected(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        apple.sign_with = attacker_key()

        with pytest.raises(ProviderRejectedError):
            await verify(client, apple.id_token(nonce=NONCE))

    async def test_tampered_payload_is_rejected(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        header, _, signature = apple.id_token(nonce=NONCE).split(".")
        _, payload, _ = apple.id_token(nonce=NONCE, sub="001234.attacker.0001").split(".")

        with pytest.raises(ProviderRejectedError):
            await verify(client, f"{header}.{payload}.{signature}")

    async def test_wrong_kid_is_rejected(self, client: AppleOAuthClient, apple: FakeApple) -> None:
        apple.header_overrides = {"kid": "unknown-kid"}

        with pytest.raises(ProviderRejectedError):
            await verify(client, apple.id_token(nonce=NONCE))

    def _claims(self, apple: FakeApple) -> dict[str, Any]:
        token = apple.id_token(nonce=NONCE)
        claims: dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
        return claims

    @pytest.mark.parametrize(
        ("algorithm", "key_factory"),
        [
            pytest.param("ES256", lambda: ec.generate_private_key(ec.SECP256R1()), id="ES256"),
            pytest.param("ES256", lambda: team_key(), id="ES256-with-our-team-key"),
            pytest.param("HS256", lambda: "x" * 32, id="HS256"),
            pytest.param("RS512", lambda: signing_key(), id="RS512-genuine-key"),
            pytest.param("PS256", lambda: signing_key(), id="PS256-genuine-key"),
        ],
    )
    async def test_algorithm_confusion_is_rejected(
        self, client: AppleOAuthClient, apple: FakeApple, algorithm: str, key_factory: Any
    ) -> None:
        """Apple signs ID tokens with RS256 only (ES256 is for *our* client secret)."""
        token = jwt.encode(
            self._claims(apple), key_factory(), algorithm=algorithm, headers={"kid": KID}
        )

        with pytest.raises(ProviderRejectedError):
            await verify(client, token)

    async def test_alg_none_is_rejected(self, client: AppleOAuthClient, apple: FakeApple) -> None:
        with pytest.raises(ProviderRejectedError):
            await verify(client, unsigned_token(**self._claims(apple)))

    @pytest.mark.parametrize("token", ["", "garbage", "a.b.c", "a" * 20_000])
    async def test_malformed_or_oversized_tokens_are_rejected(
        self, client: AppleOAuthClient, token: str
    ) -> None:
        with pytest.raises(ProviderRejectedError):
            await verify(client, token)


class TestEmail:
    @pytest.mark.parametrize("flag", ["true", True])
    async def test_verified_email_is_kept_for_string_or_boolean_true(
        self, client: AppleOAuthClient, apple: FakeApple, flag: Any
    ) -> None:
        identity = await verify(client, apple.id_token(nonce=NONCE, email_verified=flag))

        assert (identity.email, identity.email_verified) == ("gina@example.com", True)

    @pytest.mark.parametrize("flag", ["false", False, "TRUE", "yes", 1, None, ABSENT])
    async def test_anything_else_is_not_verified(
        self, client: AppleOAuthClient, apple: FakeApple, flag: Any
    ) -> None:
        identity = await verify(client, apple.id_token(nonce=NONCE, email_verified=flag))

        assert (identity.email, identity.email_verified) == (None, False)

    async def test_private_relay_email_is_stored_like_any_verified_email(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        apple.email = "X7K2Q9@privaterelay.appleid.com"
        apple.is_private_email = True

        identity = await verify(client, apple.id_token(nonce=NONCE))

        assert identity.email == "x7k2q9@privaterelay.appleid.com"

    async def test_missing_email_still_signs_in_by_sub(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        """Apple may omit the email after the first authorization; `sub` is enough."""
        apple.email = None

        identity = await verify(client, apple.id_token(nonce=NONCE))

        assert identity == ProviderIdentity(subject=apple.subject, email=None, email_verified=False)


class TestJwks:
    async def test_keys_are_cached(self, client: AppleOAuthClient, apple: FakeApple) -> None:
        for _ in range(3):
            await verify(client, apple.id_token(nonce=NONCE))

        assert apple.jwks_requests == 1

    async def test_rotated_key_triggers_one_controlled_refetch(
        self, client: AppleOAuthClient, apple: FakeApple, clock: FrozenClock
    ) -> None:
        await verify(client, apple.id_token(nonce=NONCE))
        apple.sign_with = attacker_key()
        apple.header_overrides = {"kid": "rotated"}
        apple.jwks_response = lambda: httpx.Response(
            200, json={"keys": [public_jwk(attacker_key(), "rotated")]}
        )
        clock.advance(timedelta(minutes=2))

        assert (await verify(client, apple.id_token(nonce=NONCE))).subject == apple.subject
        assert apple.jwks_requests == 2

    async def test_unknown_kids_cannot_force_repeated_refetches(
        self, client: AppleOAuthClient, apple: FakeApple
    ) -> None:
        await verify(client, apple.id_token(nonce=NONCE))
        apple.header_overrides = {"kid": "unknown"}

        for _ in range(5):
            with pytest.raises(ProviderRejectedError):
                await verify(client, apple.id_token(nonce=NONCE))

        assert apple.jwks_requests == 1

    @pytest.mark.parametrize(
        "response",
        [
            lambda: httpx.Response(503),
            lambda: httpx.Response(200, content=b"nope"),
            lambda: httpx.Response(200, json={"keys": "nope"}),
        ],
    )
    async def test_jwks_failures_mean_unavailable(
        self, client: AppleOAuthClient, apple: FakeApple, response: Any
    ) -> None:
        apple.jwks_response = response

        with pytest.raises(ProviderUnavailableError):
            await verify(client, apple.id_token(nonce=NONCE))
