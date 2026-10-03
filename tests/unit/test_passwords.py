import threading
import time
import unicodedata

import anyio
import argon2
import pytest

from app.core.passwords import (
    MAX_PASSWORD_BYTES,
    PRODUCTION_PARAMS,
    Argon2Params,
    PasswordHasher,
    PasswordTooLongError,
)

# Cheapest parameters argon2 accepts: keeps the suite fast. Production params are tested separately.
FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8, parallelism=1)
PASSWORD = "correct horse battery staple"
CAFE_COMPOSED = unicodedata.normalize("NFC", "café-latte-1234")
CAFE_DECOMPOSED = unicodedata.normalize("NFD", "café-latte-1234")


def to_fullwidth(text: str) -> str:
    """Map printable ASCII to the Unicode full-width block (U+FF01..U+FF5E)."""
    return text.translate({code: code + 0xFEE0 for code in range(0x21, 0x7F)})


@pytest.fixture
def hasher() -> PasswordHasher:
    return PasswordHasher(FAST_PARAMS)


class TestHashing:
    async def test_produces_argon2id_hash(self, hasher: PasswordHasher) -> None:
        password_hash = await hasher.hash(PASSWORD)

        assert password_hash.startswith("$argon2id$v=19$")

    async def test_hash_encodes_configured_parameters(self, hasher: PasswordHasher) -> None:
        password_hash = await hasher.hash(PASSWORD)

        assert "$m=8,t=1,p=1$" in password_hash

    async def test_same_password_gets_unique_salt(self, hasher: PasswordHasher) -> None:
        assert await hasher.hash(PASSWORD) != await hasher.hash(PASSWORD)

    async def test_hash_does_not_contain_password(self, hasher: PasswordHasher) -> None:
        assert PASSWORD not in await hasher.hash(PASSWORD)

    async def test_oversized_password_is_refused_before_hashing(
        self, hasher: PasswordHasher
    ) -> None:
        with pytest.raises(PasswordTooLongError):
            await hasher.hash("x" * (MAX_PASSWORD_BYTES + 1))

    async def test_byte_limit_counts_utf8_bytes_not_characters(
        self, hasher: PasswordHasher
    ) -> None:
        four_byte_chars = "😀" * (MAX_PASSWORD_BYTES // 4 + 1)

        with pytest.raises(PasswordTooLongError):
            await hasher.hash(four_byte_chars)

    async def test_error_does_not_echo_password(self, hasher: PasswordHasher) -> None:
        secret = "s3cret-" * 300
        with pytest.raises(PasswordTooLongError) as exc_info:
            await hasher.hash(secret)

        assert "s3cret" not in str(exc_info.value)


class TestVerification:
    async def test_correct_password_verifies(self, hasher: PasswordHasher) -> None:
        password_hash = await hasher.hash(PASSWORD)

        assert await hasher.verify(password_hash, PASSWORD) is True

    @pytest.mark.parametrize("attempt", ["wrong password!!", "", PASSWORD.upper(), PASSWORD + " "])
    async def test_wrong_password_fails(self, hasher: PasswordHasher, attempt: str) -> None:
        password_hash = await hasher.hash(PASSWORD)

        assert await hasher.verify(password_hash, attempt) is False

    @pytest.mark.parametrize(
        "stored",
        [
            "",
            "not-a-hash",
            "$argon2id$garbage",
            "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",  # bcrypt
        ],
    )
    async def test_malformed_stored_hash_fails_closed(
        self, hasher: PasswordHasher, stored: str
    ) -> None:
        assert await hasher.verify(stored, PASSWORD) is False

    async def test_oversized_attempt_fails_without_hashing(
        self, hasher: PasswordHasher, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        password_hash = await hasher.hash(PASSWORD)

        def must_not_run(*_: object) -> bool:
            raise AssertionError("argon2 verify must not run for oversized input")

        # argon2.PasswordHasher uses __slots__, so spies are patched on the class.
        monkeypatch.setattr(argon2.PasswordHasher, "verify", must_not_run)

        assert await hasher.verify(password_hash, "x" * (MAX_PASSWORD_BYTES + 1)) is False

    @pytest.mark.parametrize(
        ("registered", "attempt"),
        [
            # Same visible text, different code points: é precomposed vs e + combining accent.
            (CAFE_COMPOSED, CAFE_DECOMPOSED),
            # Full-width forms typed by some IME keyboards.
            ("password-strong-1", to_fullwidth("password") + "-strong-1"),
        ],
    )
    async def test_unicode_is_normalised(
        self, hasher: PasswordHasher, registered: str, attempt: str
    ) -> None:
        password_hash = await hasher.hash(registered)

        assert await hasher.verify(password_hash, attempt) is True


class TestRehash:
    async def test_needs_rehash_when_parameters_change(self, hasher: PasswordHasher) -> None:
        weak_hash = await hasher.hash(PASSWORD)
        stronger = PasswordHasher(Argon2Params(time_cost=2, memory_cost=16, parallelism=1))

        assert stronger.needs_rehash(weak_hash) is True

    async def test_no_rehash_for_current_parameters(self, hasher: PasswordHasher) -> None:
        assert hasher.needs_rehash(await hasher.hash(PASSWORD)) is False

    def test_malformed_hash_needs_rehash(self, hasher: PasswordHasher) -> None:
        assert hasher.needs_rehash("not-a-hash") is True


class TestTimingEqualisation:
    async def test_dummy_verify_runs_a_real_argon2_verification(
        self, hasher: PasswordHasher, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        original = argon2.PasswordHasher.verify

        def spy(self: argon2.PasswordHasher, stored: str, password: str) -> bool:
            calls.append(stored)
            return original(self, stored, password)

        monkeypatch.setattr(argon2.PasswordHasher, "verify", spy)

        await hasher.verify_dummy(PASSWORD)

        assert len(calls) == 1
        assert calls[0].startswith("$argon2id$v=19$m=8,t=1,p=1$")


class TestProductionParameters:
    def test_meet_owasp_minimums(self) -> None:
        # OWASP Password Storage Cheat Sheet: Argon2id, m >= 19 MiB, t >= 2, p >= 1.
        assert PRODUCTION_PARAMS.memory_cost >= 19 * 1024
        assert PRODUCTION_PARAMS.time_cost >= 2
        assert PRODUCTION_PARAMS.parallelism >= 1
        assert PRODUCTION_PARAMS.salt_len >= 16
        assert PRODUCTION_PARAMS.hash_len >= 32

    async def test_default_hasher_uses_production_parameters(self) -> None:
        password_hash = await PasswordHasher().hash(PASSWORD)

        assert password_hash.startswith(
            f"$argon2id$v=19$m={PRODUCTION_PARAMS.memory_cost},"
            f"t={PRODUCTION_PARAMS.time_cost},p={PRODUCTION_PARAMS.parallelism}$"
        )


class TestEventLoopSafety:
    async def test_hashing_runs_off_the_event_loop_thread(
        self, hasher: PasswordHasher, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        threads: list[int] = []
        original = argon2.PasswordHasher.hash

        def spy(self: argon2.PasswordHasher, password: str, **kwargs: object) -> str:
            threads.append(threading.get_ident())
            return original(self, password)

        monkeypatch.setattr(argon2.PasswordHasher, "hash", spy)

        await hasher.hash(PASSWORD)

        assert len(threads) == 1
        assert threads[0] != threading.get_ident()

    async def test_concurrent_hashing_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        hasher = PasswordHasher(FAST_PARAMS, max_concurrency=2)
        active = peak = 0
        lock = threading.Lock()

        def slow_hash(self: argon2.PasswordHasher, password: str, **kwargs: object) -> str:
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.02)
            with lock:
                active -= 1
            return "$argon2id$fake"

        monkeypatch.setattr(argon2.PasswordHasher, "hash", slow_hash)

        async with anyio.create_task_group() as tg:
            for _ in range(8):
                tg.start_soon(hasher.hash, PASSWORD)

        assert peak == 2
