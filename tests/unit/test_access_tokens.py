import base64
import contextlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest

from app.core.config import Settings
from app.core.tokens import (
    ACCESS_TOKEN_TYPE,
    LEEWAY,
    MAX_TOKEN_LENGTH,
    AccessTokenService,
    InvalidTokenError,
)
from tests.support.clock import FrozenClock

USER_ID = uuid.UUID("01890a5d-ac96-7b3c-9c3a-6f2d1e4b5a01")
SESSION_ID = uuid.UUID("01890a5d-ac96-7b3c-9c3a-6f2d1e4b5a02")


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def service(test_settings: Settings, clock: FrozenClock) -> AccessTokenService:
    return AccessTokenService(test_settings, clock=clock)


@pytest.fixture
def secret(test_settings: Settings) -> str:
    return test_settings.jwt_secret.get_secret_value()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64_json(value: Any) -> str:
    return b64(json.dumps(value).encode())


def valid_claims(settings: Settings, clock: FrozenClock, **overrides: Any) -> dict[str, Any]:
    now = int(clock().timestamp())
    claims: dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(USER_ID),
        "sid": str(SESSION_ID),
        "typ": ACCESS_TOKEN_TYPE,
        "iat": now,
        "nbf": now,
        "exp": now + 900,
        "jti": str(uuid.uuid4()),
    }
    claims.update(overrides)
    return claims


def forge(claims: dict[str, Any], key: str, algorithm: str = "HS256") -> str:
    """Sign arbitrary JSON directly: jwt.encode() refuses some malicious claims (e.g. iss=None)."""
    signer = jwt.get_algorithm_by_name(algorithm)
    signing_input = f"{b64_json({'alg': algorithm, 'typ': 'JWT'})}.{b64_json(claims)}"
    signature = signer.sign(signing_input.encode(), signer.prepare_key(key))
    return f"{signing_input}.{b64(signature)}"


def assert_invalid(service: AccessTokenService, token: str) -> None:
    with pytest.raises(InvalidTokenError) as exc_info:
        service.decode(token)

    # One consistent error: same message, no chained cause, nothing from the token echoed back.
    error = exc_info.value
    assert str(error) == "invalid token"
    # No underlying PyJWT/ValueError attached that a traceback or log could expose.
    assert error.__cause__ is None
    assert error.__context__ is None or error.__suppress_context__


class TestIssue:
    def test_round_trip(self, service: AccessTokenService) -> None:
        issued = service.issue(user_id=USER_ID, session_id=SESSION_ID)

        claims = service.decode(issued.token)

        assert claims.user_id == USER_ID
        assert claims.session_id == SESSION_ID

    def test_contains_all_required_claims(
        self, service: AccessTokenService, test_settings: Settings, clock: FrozenClock
    ) -> None:
        issued = service.issue(user_id=USER_ID, session_id=SESSION_ID)
        payload = jwt.decode(issued.token, options={"verify_signature": False})

        assert set(payload) == {"iss", "aud", "sub", "sid", "typ", "iat", "nbf", "exp", "jti"}
        assert payload["iss"] == test_settings.jwt_issuer
        assert payload["aud"] == test_settings.jwt_audience
        assert payload["typ"] == "access"
        assert payload["iat"] == payload["nbf"] == int(clock().timestamp())

    def test_expires_after_configured_minutes(
        self, service: AccessTokenService, test_settings: Settings, clock: FrozenClock
    ) -> None:
        issued = service.issue(user_id=USER_ID, session_id=SESSION_ID)
        payload = jwt.decode(issued.token, options={"verify_signature": False})

        lifetime = test_settings.access_token_expire_minutes * 60
        assert lifetime == 15 * 60
        assert payload["exp"] - payload["iat"] == lifetime
        assert issued.expires_in == lifetime
        assert issued.expires_at == clock() + timedelta(seconds=lifetime)

    def test_uses_configured_algorithm_in_header(
        self, service: AccessTokenService, test_settings: Settings
    ) -> None:
        token = service.issue(user_id=USER_ID, session_id=SESSION_ID).token

        assert jwt.get_unverified_header(token) == {
            "alg": test_settings.jwt_algorithm,
            "typ": "JWT",
        }

    def test_each_token_has_unique_jti(self, service: AccessTokenService) -> None:
        tokens = [service.issue(user_id=USER_ID, session_id=SESSION_ID) for _ in range(5)]

        assert len({service.decode(t.token).token_id for t in tokens}) == 5

    def test_secret_never_appears_in_token(self, service: AccessTokenService, secret: str) -> None:
        token = service.issue(user_id=USER_ID, session_id=SESSION_ID).token

        assert secret not in token
        assert secret not in json.dumps(jwt.decode(token, options={"verify_signature": False}))


class TestTimeValidation:
    def test_valid_just_before_expiry(
        self, service: AccessTokenService, clock: FrozenClock
    ) -> None:
        token = service.issue(user_id=USER_ID, session_id=SESSION_ID).token

        clock.advance(timedelta(minutes=15) + LEEWAY)

        assert service.decode(token).user_id == USER_ID

    def test_expired_token_is_rejected(
        self, service: AccessTokenService, clock: FrozenClock
    ) -> None:
        token = service.issue(user_id=USER_ID, session_id=SESSION_ID).token

        clock.advance(timedelta(minutes=15) + LEEWAY + timedelta(seconds=1))

        assert_invalid(service, token)

    def test_not_yet_valid_token_is_rejected(
        self, service: AccessTokenService, test_settings: Settings, clock: FrozenClock, secret: str
    ) -> None:
        future = int((clock() + timedelta(minutes=5)).timestamp())
        token = forge(valid_claims(test_settings, clock, nbf=future), secret)

        assert_invalid(service, token)

    def test_small_clock_skew_is_tolerated(
        self, service: AccessTokenService, test_settings: Settings, clock: FrozenClock, secret: str
    ) -> None:
        slightly_ahead = int((clock() + LEEWAY).timestamp())
        token = forge(
            valid_claims(test_settings, clock, nbf=slightly_ahead, iat=slightly_ahead), secret
        )

        assert service.decode(token).user_id == USER_ID

    def test_token_issued_in_the_future_is_rejected(
        self, service: AccessTokenService, test_settings: Settings, clock: FrozenClock, secret: str
    ) -> None:
        future = int((clock() + timedelta(hours=1)).timestamp())
        token = forge(valid_claims(test_settings, clock, iat=future), secret)

        assert_invalid(service, token)

    @pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
    @pytest.mark.parametrize("bad_value", ["1767225600", True, 1.5e30, None, [1]])
    def test_non_integer_time_claims_are_rejected(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        claim: str,
        bad_value: Any,
    ) -> None:
        token = forge(valid_claims(test_settings, clock, **{claim: bad_value}), secret)

        assert_invalid(service, token)

    @pytest.mark.parametrize("iat_offset", [timedelta(hours=-1), timedelta(days=-20_000)])
    def test_lifetime_longer_than_configured_is_rejected(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        iat_offset: timedelta,
    ) -> None:
        # Correctly signed, currently unexpired, but claims a lifetime far beyond 15 minutes.
        issued = int((clock() + iat_offset).timestamp())
        token = forge(valid_claims(test_settings, clock, iat=issued, nbf=issued), secret)

        assert_invalid(service, token)

    def test_exp_before_iat_is_rejected(
        self, service: AccessTokenService, test_settings: Settings, clock: FrozenClock, secret: str
    ) -> None:
        now = int(clock().timestamp())
        token = forge(valid_claims(test_settings, clock, iat=now, exp=now - 1), secret)

        assert_invalid(service, token)

    def test_uses_injected_clock_not_wall_clock(self, test_settings: Settings, secret: str) -> None:
        # Token valid "in 2030" but the wall clock says otherwise: only the injected clock counts.
        clock_2030 = FrozenClock(datetime(2030, 6, 1, tzinfo=UTC))
        service = AccessTokenService(test_settings, clock=clock_2030)

        token = service.issue(user_id=USER_ID, session_id=SESSION_ID).token

        assert service.decode(token).user_id == USER_ID


class TestSignatureAndAlgorithm:
    def test_wrong_secret_is_rejected(
        self, service: AccessTokenService, test_settings: Settings, clock: FrozenClock
    ) -> None:
        other_secret = "a-completely-different-but-long-secret-value-9f8e7d"
        token = forge(valid_claims(test_settings, clock), other_secret)

        assert_invalid(service, token)

    def test_tampered_payload_is_rejected(self, service: AccessTokenService) -> None:
        header, payload, signature = service.issue(
            user_id=USER_ID, session_id=SESSION_ID
        ).token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
        claims["sub"] = str(uuid.uuid4())  # impersonate another user

        assert_invalid(service, f"{header}.{b64_json(claims)}.{signature}")

    def test_tampered_signature_is_rejected(self, service: AccessTokenService) -> None:
        header, payload, signature = service.issue(
            user_id=USER_ID, session_id=SESSION_ID
        ).token.split(".")
        # Flip a middle character: the last base64 char can carry only padding bits.
        middle = len(signature) // 2
        flipped = "A" if signature[middle] != "A" else "B"
        tampered = signature[:middle] + flipped + signature[middle + 1 :]

        assert_invalid(service, f"{header}.{payload}.{tampered}")

    def test_stripped_signature_is_rejected(self, service: AccessTokenService) -> None:
        header, payload, _ = service.issue(user_id=USER_ID, session_id=SESSION_ID).token.split(".")

        assert_invalid(service, f"{header}.{payload}.")

    @pytest.mark.parametrize("alg", ["none", "None", "NONE"])
    def test_alg_none_is_rejected(
        self, service: AccessTokenService, test_settings: Settings, clock: FrozenClock, alg: str
    ) -> None:
        header = b64_json({"alg": alg, "typ": "JWT"})
        token = f"{header}.{b64_json(valid_claims(test_settings, clock))}."  # empty signature

        assert_invalid(service, token)

    @pytest.mark.parametrize("alg", ["HS384", "HS512"])
    def test_other_hmac_algorithms_are_rejected(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        alg: str,
    ) -> None:
        # Correctly signed with the real secret, but not with the one configured algorithm.
        assert_invalid(service, forge(valid_claims(test_settings, clock), secret, algorithm=alg))

    @pytest.mark.parametrize("alg", ["RS256", "ES256", "PS256", "EdDSA", "hs256"])
    def test_algorithm_confusion_is_rejected(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        alg: str,
    ) -> None:
        # Header claims another algorithm; signature computed with HMAC over the shared secret.
        signing_input = (
            f"{b64_json({'alg': alg, 'typ': 'JWT'})}.{b64_json(valid_claims(test_settings, clock))}"
        )
        signature = jwt.get_algorithm_by_name("HS256").sign(
            signing_input.encode(), jwt.get_algorithm_by_name("HS256").prepare_key(secret)
        )

        assert_invalid(service, f"{signing_input}.{b64(signature)}")


class TestRequiredClaims:
    @pytest.mark.parametrize(
        "claim", ["iss", "aud", "sub", "sid", "typ", "iat", "nbf", "exp", "jti"]
    )
    def test_missing_claim_is_rejected(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        claim: str,
    ) -> None:
        claims = valid_claims(test_settings, clock)
        del claims[claim]

        assert_invalid(service, forge(claims, secret))

    @pytest.mark.parametrize(
        "issuer", ["evil-issuer", "", "HOME-INVENTORY-API", None, ["home-inventory-api"]]
    )
    def test_wrong_issuer_is_rejected(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        issuer: Any,
    ) -> None:
        assert_invalid(service, forge(valid_claims(test_settings, clock, iss=issuer), secret))

    @pytest.mark.parametrize(
        "audience",
        [
            "other-app",
            "",
            None,
            ["other-app"],
            # A list containing ours plus another is a token minted for someone else too.
            ["home-inventory-mobile", "other-app"],
            ["home-inventory-mobile"],
        ],
    )
    def test_wrong_or_non_strict_audience_is_rejected(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        audience: Any,
    ) -> None:
        assert_invalid(service, forge(valid_claims(test_settings, clock, aud=audience), secret))

    @pytest.mark.parametrize("token_type", ["refresh", "Access", "id", "", None, ["access"]])
    def test_wrong_token_type_is_rejected(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        token_type: Any,
    ) -> None:
        assert_invalid(service, forge(valid_claims(test_settings, clock, typ=token_type), secret))

    @pytest.mark.parametrize("claim", ["sub", "sid", "jti"])
    @pytest.mark.parametrize(
        "bad_value",
        [
            "not-a-uuid",
            "",
            12345,
            None,
            f"{{{USER_ID}}}",  # braces: accepted by uuid.UUID(), never issued by us
            f"urn:uuid:{USER_ID}",
            USER_ID.hex,  # no hyphens
            str(USER_ID).upper(),
        ],
    )
    def test_identifier_claims_must_be_canonical_uuids(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        claim: str,
        bad_value: Any,
    ) -> None:
        assert_invalid(
            service, forge(valid_claims(test_settings, clock, **{claim: bad_value}), secret)
        )


class TestMalformedInput:
    @pytest.mark.parametrize(
        "token",
        [
            "",
            "abc",
            "a.b",
            "a.b.c",
            "a.b.c.d",
            "...",
            "Bearer x.y.z",
            "é.é.é",
            f"{b64(b'not json')}.{b64_json({})}.sig",
            f"{b64_json({'alg': 'HS256'})}.{b64(b'not json')}.sig",
            f"{b64_json({'alg': 'HS256'})}.{b64_json([1, 2, 3])}.sig",
            f"{b64_json(['HS256'])}.{b64_json({})}.sig",
        ],
    )
    def test_malformed_tokens_are_rejected(self, service: AccessTokenService, token: str) -> None:
        assert_invalid(service, token)

    def test_oversized_token_is_rejected_before_parsing(
        self,
        service: AccessTokenService,
        test_settings: Settings,
        clock: FrozenClock,
        secret: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Correctly signed and otherwise valid, but padded past the size limit.
        token = forge(valid_claims(test_settings, clock, pad="x" * MAX_TOKEN_LENGTH), secret)

        def must_not_parse(*_: object, **__: object) -> None:
            raise AssertionError("oversized tokens must be rejected before parsing")

        monkeypatch.setattr(jwt, "decode", must_not_parse)
        monkeypatch.setattr(jwt, "get_unverified_header", must_not_parse)

        assert_invalid(service, token)

    def test_garbage_of_maximum_length_is_rejected(self, service: AccessTokenService) -> None:
        assert_invalid(service, "a" * 10_000)

    def test_error_never_contains_token(
        self, service: AccessTokenService, test_settings: Settings, clock: FrozenClock
    ) -> None:
        token = forge(valid_claims(test_settings, clock), "wrong-secret-but-long-enough-xyz-123")

        with pytest.raises(InvalidTokenError) as exc_info:
            service.decode(token)

        assert token not in str(exc_info.value)
        assert token not in repr(exc_info.value)


ODD_VALUES: list[Any] = [None, True, 0, -1, 2**70, 1.5, "", "x", [], [1], {}, {"a": 1}, "\x00"]


@pytest.mark.parametrize("claim", ["iss", "aud", "sub", "sid", "typ", "iat", "nbf", "exp", "jti"])
def test_decode_only_ever_raises_invalid_token_error(
    service: AccessTokenService,
    test_settings: Settings,
    clock: FrozenClock,
    secret: str,
    claim: str,
) -> None:
    """Regression guard: any other exception type would surface as a 500 in the API.

    Acceptance/rejection of specific values is covered by the targeted tests above.
    """
    for value in ODD_VALUES:
        token = forge(valid_claims(test_settings, clock, **{claim: value}), secret)
        with contextlib.suppress(InvalidTokenError):
            service.decode(token)


def test_raw_tokens_and_secret_are_never_logged(
    service: AccessTokenService,
    test_settings: Settings,
    clock: FrozenClock,
    secret: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Covers our code and PyJWT's loggers, for both successful and failed validation."""
    caplog.set_level(logging.DEBUG)
    good = service.issue(user_id=USER_ID, session_id=SESSION_ID).token
    bad = forge(valid_claims(test_settings, clock), "wrong-secret-but-long-enough-xyz-123")

    service.decode(good)
    with contextlib.suppress(InvalidTokenError):
        service.decode(bad)

    logged = "\n".join(
        f"{record.getMessage()} {record.exc_text or ''}" for record in caplog.records
    )
    for sensitive in (good, bad, secret, *good.split("."), *bad.split(".")):
        assert sensitive not in logged
