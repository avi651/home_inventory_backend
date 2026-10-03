"""Rate limiting behind a small protocol so a Redis implementation can replace the in-memory one.

The in-memory limiter is per process: with several workers/instances each keeps its own counts,
so production needs a shared backend (Redis) behind the same protocol.
"""

import asyncio
import hashlib
import math
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from app.core.clock import Clock, utc_now


@dataclass(frozen=True)
class RateLimit:
    limit: int
    window: timedelta


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int = 0  # whole seconds until a slot frees up


@dataclass(frozen=True)
class AuthRateLimits:
    register_per_ip: RateLimit
    login_per_ip: RateLimit
    login_per_account: RateLimit
    refresh_per_ip: RateLimit
    guest_per_ip: RateLimit


DEFAULT_AUTH_RATE_LIMITS = AuthRateLimits(
    register_per_ip=RateLimit(limit=5, window=timedelta(hours=1)),
    login_per_ip=RateLimit(limit=10, window=timedelta(minutes=1)),
    login_per_account=RateLimit(limit=5, window=timedelta(minutes=15)),
    refresh_per_ip=RateLimit(limit=30, window=timedelta(minutes=1)),
    guest_per_ip=RateLimit(limit=10, window=timedelta(hours=1)),
)


class RateLimiter(Protocol):
    async def hit(self, key: str, rule: RateLimit) -> RateLimitResult: ...


def account_key(normalized_email: str) -> str:
    """Account-scoped key without keeping the email itself in limiter memory (or Redis)."""
    return hashlib.sha256(normalized_email.encode()).hexdigest()[:32]


class InMemoryRateLimiter:
    """Sliding-window log. Rejected attempts are not recorded, so they don't extend the window."""

    def __init__(self, clock: Clock = utc_now) -> None:
        self._clock = clock
        self._hits: dict[str, tuple[deque[datetime], timedelta]] = {}
        self._lock = asyncio.Lock()

    async def hit(self, key: str, rule: RateLimit) -> RateLimitResult:
        async with self._lock:
            now = self._clock()
            self._prune(now)
            hits, _ = self._hits.setdefault(key, (deque(), rule.window))
            while hits and hits[0] <= now - rule.window:
                hits.popleft()
            if len(hits) >= rule.limit:
                wait = (hits[0] + rule.window - now).total_seconds()
                return RateLimitResult(allowed=False, retry_after=max(1, math.ceil(wait)))
            hits.append(now)
            self._hits[key] = (hits, rule.window)
            return RateLimitResult(allowed=True)

    def tracked_keys(self) -> int:
        return len(self._hits)

    def _prune(self, now: datetime) -> None:
        expired = [
            k for k, (hits, window) in self._hits.items() if not hits or hits[-1] <= now - window
        ]
        for key in expired:
            del self._hits[key]
