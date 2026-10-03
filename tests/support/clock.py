from datetime import UTC, datetime, timedelta


class FrozenClock:
    """Deterministic clock for tests: returns a fixed instant until advanced."""

    def __init__(self, now: datetime | None = None) -> None:
        self.now = now or datetime(2026, 1, 15, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta
