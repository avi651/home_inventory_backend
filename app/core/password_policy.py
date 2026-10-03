import unicodedata
from enum import StrEnum
from functools import cache
from pathlib import Path

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MIN_EMAIL_LOCAL_PART_TO_MATCH = 3
_COMMON_PASSWORDS_FILE = Path(__file__).parent / "data" / "common_passwords.txt"
# Zero-width joiner is legitimate inside emoji sequences; every other format char is invisible.
_ALLOWED_FORMAT_CHARS = frozenset({"‍"})


class PasswordViolation(StrEnum):
    """Stable codes for API responses. Never carry the password itself."""

    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    BLANK = "blank"
    INVALID_CHARACTERS = "invalid_characters"
    COMMON = "common"
    CONTAINS_EMAIL = "contains_email"


@cache
def _common_passwords() -> frozenset[str]:
    lines = _COMMON_PASSWORDS_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(line.casefold() for line in lines if line.strip() and not line.startswith("#"))


def _has_invalid_characters(password: str) -> bool:
    return any(
        unicodedata.category(ch) in {"Cc", "Cf"} and ch not in _ALLOWED_FORMAT_CHARS
        for ch in password
    )


def check_password(password: str, email: str | None = None) -> list[PasswordViolation]:
    """NIST SP 800-63B style checks: length, blocklist, context. No composition rules."""
    if len(password) > MAX_PASSWORD_LENGTH * 4:  # never normalise unbounded input
        return [PasswordViolation.TOO_LONG]

    normalised = unicodedata.normalize("NFKC", password)
    folded = normalised.casefold()
    violations: list[PasswordViolation] = []

    if len(normalised) < MIN_PASSWORD_LENGTH:
        violations.append(PasswordViolation.TOO_SHORT)
    if len(normalised) > MAX_PASSWORD_LENGTH:
        violations.append(PasswordViolation.TOO_LONG)
    if not normalised.strip():
        violations.append(PasswordViolation.BLANK)
    if _has_invalid_characters(normalised):
        violations.append(PasswordViolation.INVALID_CHARACTERS)
    if folded in _common_passwords() or len(set(normalised)) == 1:
        violations.append(PasswordViolation.COMMON)
    if email:
        local_part = email.split("@", 1)[0].casefold()
        if len(local_part) >= MIN_EMAIL_LOCAL_PART_TO_MATCH and local_part in folded:
            violations.append(PasswordViolation.CONTAINS_EMAIL)

    return violations
