import base64
import hmac
import re
import secrets

import pytest

from app.core.refresh_tokens import (
    REFRESH_TOKEN_PREFIX,
    generate_refresh_token,
    hash_refresh_token,
    hashes_match,
    is_well_formed,
)

BODY_LENGTH = 43  # base64url of 32 bytes, unpadded


class TestGeneration:
    def test_format_is_prefix_plus_urlsafe_body(self) -> None:
        token = generate_refresh_token()

        assert token.startswith(REFRESH_TOKEN_PREFIX)
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token.removeprefix(REFRESH_TOKEN_PREFIX))

    def test_carries_256_bits_of_entropy(self) -> None:
        body = generate_refresh_token().removeprefix(REFRESH_TOKEN_PREFIX)

        assert len(base64.urlsafe_b64decode(body + "=")) == 32

    def test_uses_the_csprng(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[int | None] = []
        original = secrets.token_urlsafe

        def spy(nbytes: int | None = None) -> str:
            calls.append(nbytes)
            return original(nbytes)

        monkeypatch.setattr(secrets, "token_urlsafe", spy)

        generate_refresh_token()

        assert calls == [32]

    def test_tokens_are_unique(self) -> None:
        assert len({generate_refresh_token() for _ in range(2000)}) == 2000

    def test_is_not_a_jwt(self) -> None:
        assert generate_refresh_token().count(".") == 0


class TestHashing:
    def test_hash_is_64_lowercase_hex(self) -> None:
        assert re.fullmatch(r"[0-9a-f]{64}", hash_refresh_token(generate_refresh_token()))

    def test_hash_is_deterministic(self) -> None:
        token = generate_refresh_token()

        assert hash_refresh_token(token) == hash_refresh_token(token)

    def test_different_tokens_have_different_hashes(self) -> None:
        assert hash_refresh_token(generate_refresh_token()) != hash_refresh_token(
            generate_refresh_token()
        )

    def test_hash_reveals_nothing_of_the_token(self) -> None:
        token = generate_refresh_token()
        digest = hash_refresh_token(token)

        assert token not in digest
        assert token.removeprefix(REFRESH_TOKEN_PREFIX)[:8] not in digest

    def test_comparison_is_constant_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[tuple[str, str]] = []
        original = hmac.compare_digest

        def spy(a: str, b: str) -> bool:
            calls.append((a, b))
            return original(a, b)

        monkeypatch.setattr(hmac, "compare_digest", spy)
        digest = hash_refresh_token(generate_refresh_token())

        assert hashes_match(digest, digest) is True
        assert hashes_match(digest, "0" * 64) is False
        assert len(calls) == 2


class TestWellFormed:
    def test_generated_tokens_are_well_formed(self) -> None:
        assert is_well_formed(generate_refresh_token())

    @pytest.mark.parametrize(
        "candidate",
        [
            "",
            REFRESH_TOKEN_PREFIX,
            "x" * 51,
            "other_rt_" + "a" * BODY_LENGTH,
            REFRESH_TOKEN_PREFIX + "a" * (BODY_LENGTH - 1),
            REFRESH_TOKEN_PREFIX + "a" * (BODY_LENGTH + 1),
            REFRESH_TOKEN_PREFIX + "a" * (BODY_LENGTH - 1) + "+",
            REFRESH_TOKEN_PREFIX + "a" * (BODY_LENGTH - 1) + "=",
            REFRESH_TOKEN_PREFIX + "a" * (BODY_LENGTH - 1) + "é",
            " " + REFRESH_TOKEN_PREFIX + "a" * BODY_LENGTH,
            REFRESH_TOKEN_PREFIX + "a" * BODY_LENGTH + "\n",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",  # an access token is not a refresh token
            "a" * 10_000,
        ],
    )
    def test_rejects_malformed_values(self, candidate: str) -> None:
        assert is_well_formed(candidate) is False
