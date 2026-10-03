from datetime import UTC, datetime, timedelta

from app.core.clock import utc_now


def test_utc_now_is_timezone_aware_utc() -> None:
    # Naive datetimes would silently break token expiry comparisons.
    now = utc_now()

    assert now.tzinfo is UTC
    assert abs(now - datetime.now(UTC)) < timedelta(seconds=5)
