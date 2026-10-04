"""Room field rules: the Homes name normalization and name-key conventions, room-specific errors.

Validation errors carry fixed messages only: user input is never echoed.
"""

from app.core.home_fields import (
    MAX_HOME_NAME_LENGTH,
    InvalidHomeNameError,
    home_name_key,
    normalize_home_name,
)

# Normalization is delegated to the Homes rules, which enforce their own limit: keep them equal.
MAX_ROOM_NAME_LENGTH = MAX_HOME_NAME_LENGTH


class InvalidRoomNameError(ValueError):
    def __init__(self) -> None:
        super().__init__("invalid room name")


def normalize_room_name(raw: str) -> str:
    """NFC, no invisible/control characters, whitespace trimmed and collapsed, 1-100 chars."""
    try:
        return normalize_home_name(raw)
    except InvalidHomeNameError:
        raise InvalidRoomNameError from None


def room_name_key(name: str) -> str:
    """Uniqueness key within a home: same case/compatibility-folded SHA-256 digest as homes."""
    return home_name_key(name)
