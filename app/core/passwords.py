import unicodedata
from dataclasses import dataclass

import anyio
import argon2
from argon2.exceptions import InvalidHashError, VerificationError

# Hard cap applied before any hashing work. The password policy caps characters (128); this caps
# UTF-8 bytes so hashing input is bounded even if a caller skips the policy.
MAX_PASSWORD_BYTES = 1024
_DUMMY_PASSWORD = "timing-equalisation-dummy-password"  # noqa: S105 - not a credential


class PasswordTooLongError(ValueError):
    def __init__(self) -> None:
        super().__init__(f"password exceeds {MAX_PASSWORD_BYTES} bytes")


@dataclass(frozen=True)
class Argon2Params:
    time_cost: int
    memory_cost: int  # KiB
    parallelism: int
    hash_len: int = 32
    salt_len: int = 16


# RFC 9106 "low memory" profile (argon2-cffi default): 64 MiB, 3 passes, 4 lanes.
PRODUCTION_PARAMS = Argon2Params(time_cost=3, memory_cost=64 * 1024, parallelism=4)


def _normalise(password: str) -> str:
    """NFKC so visually identical input (composed/decomposed, full-width) hashes identically."""
    if len(password) > MAX_PASSWORD_BYTES:  # cheap pre-check: never normalise huge input
        raise PasswordTooLongError
    normalised = unicodedata.normalize("NFKC", password)
    if len(normalised.encode()) > MAX_PASSWORD_BYTES:
        raise PasswordTooLongError
    return normalised


class PasswordHasher:
    """Argon2id hashing that never blocks the event loop and bounds concurrent memory use."""

    def __init__(self, params: Argon2Params = PRODUCTION_PARAMS, max_concurrency: int = 4) -> None:
        self._argon2 = argon2.PasswordHasher(
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            salt_len=params.salt_len,
            type=argon2.Type.ID,
        )
        # Each hash holds memory_cost KiB; the limiter caps peak memory and CPU per process.
        self._limiter = anyio.CapacityLimiter(max_concurrency)
        # Computed once with the same parameters so unknown-user logins cost the same as real ones.
        self._dummy_hash = self._argon2.hash(_DUMMY_PASSWORD)

    async def hash(self, password: str) -> str:
        normalised = _normalise(password)
        return await anyio.to_thread.run_sync(self._argon2.hash, normalised, limiter=self._limiter)

    async def verify(self, password_hash: str, password: str) -> bool:
        """True only for a correct password; any malformed input fails closed."""
        try:
            normalised = _normalise(password)
            return await anyio.to_thread.run_sync(
                self._argon2.verify, password_hash, normalised, limiter=self._limiter
            )
        except PasswordTooLongError, VerificationError, InvalidHashError:
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        try:
            return self._argon2.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True

    async def verify_dummy(self, password: str) -> None:
        """Spend the same work as a real verification; used when no account matches."""
        await self.verify(self._dummy_hash, password)
