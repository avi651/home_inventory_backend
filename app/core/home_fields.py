"""Home field rules: display-safe names, a case-insensitive name key, ISO 4217 currencies.

Validation errors carry fixed messages only: user input is never echoed.
"""

import hashlib
import re
import unicodedata
from functools import cache
from pathlib import Path

MAX_HOME_NAME_LENGTH = 100
_CURRENCY_FILE = Path(__file__).parent / "data" / "iso4217.txt"
_CURRENCY_SHAPE = re.compile(r"[A-Z]{3}")
# Control, format (zero-width, bidi overrides, joiners), line/paragraph separators, surrogates,
# private-use and unassigned code points: invisible or spoofable in a name shown in a UI.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


class InvalidHomeNameError(ValueError):
    def __init__(self) -> None:
        super().__init__("invalid home name")


class InvalidCurrencyError(ValueError):
    def __init__(self) -> None:
        super().__init__("invalid currency code")


def normalize_home_name(raw: str) -> str:
    """NFC, no invisible/control characters, whitespace trimmed and collapsed, 1-100 chars."""
    if len(raw) > MAX_HOME_NAME_LENGTH * 4:  # never normalise unbounded input
        raise InvalidHomeNameError
    name = unicodedata.normalize("NFC", raw)
    if any(unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in name):
        raise InvalidHomeNameError
    name = " ".join(name.split())  # any Unicode whitespace run -> one ASCII space
    if not 1 <= len(name) <= MAX_HOME_NAME_LENGTH:
        raise InvalidHomeNameError
    return name


def home_name_key(name: str) -> str:
    """Uniqueness key: SHA-256 of NFKC(casefold(NFKC(name))).

    "Home", "HOME" and a fullwidth "HOME" (U+FF28...) collide, as do "Strasse" spelled with a
    sharp s (U+00DF) and "STRASSE". A digest, because folding can expand text far beyond the
    100-character name limit.
    """
    folded = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", name).casefold())
    return hashlib.sha256(folded.encode()).hexdigest()


@cache
def _currencies() -> frozenset[str]:
    lines = _CURRENCY_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip() for line in lines if line.strip() and not line.startswith("#"))


def normalize_currency(raw: str) -> str:
    code = raw.strip().upper()
    if not _CURRENCY_SHAPE.fullmatch(code) or code not in _currencies():
        raise InvalidCurrencyError
    return code
