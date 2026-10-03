from datetime import timedelta

import anyio
import pytest

from app.core.rate_limit import (
    DEFAULT_AUTH_RATE_LIMITS,
    InMemoryRateLimiter,
    RateLimit,
    account_key,
)
from tests.support.clock import FrozenClock

RULE = RateLimit(limit=3, window=timedelta(minutes=1))


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def limiter(clock: FrozenClock) -> InMemoryRateLimiter:
    return InMemoryRateLimiter(clock=clock)


async def test_allows_up_to_the_limit(limiter: InMemoryRateLimiter) -> None:
    results = [await limiter.hit("k", RULE) for _ in range(3)]

    assert all(r.allowed for r in results)


async def test_blocks_beyond_the_limit_with_retry_after(
    limiter: InMemoryRateLimiter, clock: FrozenClock
) -> None:
    for _ in range(3):
        await limiter.hit("k", RULE)
    clock.advance(timedelta(seconds=20))

    blocked = await limiter.hit("k", RULE)

    assert blocked.allowed is False
    assert blocked.retry_after == 40


async def test_sliding_window_frees_capacity(
    limiter: InMemoryRateLimiter, clock: FrozenClock
) -> None:
    for _ in range(3):
        await limiter.hit("k", RULE)
    clock.advance(timedelta(minutes=1))

    assert (await limiter.hit("k", RULE)).allowed is True


async def test_blocked_attempts_do_not_extend_the_window(
    limiter: InMemoryRateLimiter, clock: FrozenClock
) -> None:
    for _ in range(3):
        await limiter.hit("k", RULE)
    for _ in range(10):
        clock.advance(timedelta(seconds=5))
        await limiter.hit("k", RULE)

    clock.advance(timedelta(seconds=10))  # 60s after the first allowed hit

    assert (await limiter.hit("k", RULE)).allowed is True


async def test_keys_are_independent(limiter: InMemoryRateLimiter) -> None:
    for _ in range(3):
        await limiter.hit("a", RULE)

    assert (await limiter.hit("b", RULE)).allowed is True
    assert (await limiter.hit("a", RULE)).allowed is False


async def test_concurrent_hits_never_exceed_the_limit(limiter: InMemoryRateLimiter) -> None:
    allowed = 0

    async def hit() -> None:
        nonlocal allowed
        if (await limiter.hit("k", RULE)).allowed:
            allowed += 1

    async with anyio.create_task_group() as tg:
        for _ in range(50):
            tg.start_soon(hit)

    assert allowed == 3


async def test_expired_keys_are_pruned(limiter: InMemoryRateLimiter, clock: FrozenClock) -> None:
    for i in range(100):
        await limiter.hit(f"k{i}", RULE)
    clock.advance(timedelta(minutes=2))

    await limiter.hit("fresh", RULE)

    assert limiter.tracked_keys() == 1


def test_account_key_does_not_contain_the_email() -> None:
    key = account_key("alice@example.com")

    assert "alice" not in key
    assert key == account_key("alice@example.com")
    assert key != account_key("bob@example.com")


def test_default_auth_limits() -> None:
    limits = DEFAULT_AUTH_RATE_LIMITS

    assert (limits.login_per_ip.limit, limits.login_per_ip.window) == (10, timedelta(minutes=1))
    assert (limits.login_per_account.limit, limits.login_per_account.window) == (
        5,
        timedelta(minutes=15),
    )
    assert (limits.register_per_ip.limit, limits.register_per_ip.window) == (5, timedelta(hours=1))
    assert (limits.refresh_per_ip.limit, limits.refresh_per_ip.window) == (30, timedelta(minutes=1))
