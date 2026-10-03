"""Home name and currency rules (unit).

Invisible and look-alike characters are written as escapes so the source stays readable.
"""

import pytest

from app.core.home_fields import (
    MAX_HOME_NAME_LENGTH,
    InvalidCurrencyError,
    InvalidHomeNameError,
    home_name_key,
    normalize_currency,
    normalize_home_name,
)

NBSP, EM_SPACE = "\u00a0", "\u2003"
FULLWIDTH_HOME = "\uff28\uff2f\uff2d\uff25"
COMBINING_ACUTE = "\u0301"


class TestName:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Home", "Home"),
            ("  Beach House  ", "Beach House"),
            (f"My   Lake{NBSP} Cabin", "My Lake Cabin"),  # internal runs (incl. NBSP) collapse
            ("Ferienhaus M\u00fcller", "Ferienhaus M\u00fcller"),
            (
                "\u6771\u4eac\u306e\u30a2\u30d1\u30fc\u30c8",
                "\u6771\u4eac\u306e\u30a2\u30d1\u30fc\u30c8",
            ),
            ("\U0001f3e0 Main", "\U0001f3e0 Main"),
            (f"Cafe{COMBINING_ACUTE}", "Caf\u00e9"),  # NFC: combining accent composed
        ],
    )
    def test_valid_names_are_normalized(self, raw: str, expected: str) -> None:
        assert normalize_home_name(raw) == expected

    def test_max_length_is_inclusive(self) -> None:
        name = "a" * MAX_HOME_NAME_LENGTH

        assert normalize_home_name(name) == name

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            NBSP + EM_SPACE,
            "a" * (MAX_HOME_NAME_LENGTH + 1),
            "line\nbreak",
            "tab\there",
            "nul\x00byte",
            "bidi\u202eemoH",  # right-to-left override (spoofing)
            "zero\u200bwidth",
            "joiner\u200dhidden",
            "para\u2029sep",
            "private\ue000use",
            "unassigned\U000e0080x",
        ],
    )
    def test_invalid_names_are_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidHomeNameError):
            normalize_home_name(raw)

    def test_oversized_input_is_rejected_before_normalization_work(self) -> None:
        with pytest.raises(InvalidHomeNameError):
            normalize_home_name("a" * 1_000_000)

    def test_error_message_never_echoes_input(self) -> None:
        with pytest.raises(InvalidHomeNameError) as exc_info:
            normalize_home_name("secret\x00name")

        assert "secret" not in str(exc_info.value)


class TestNameKey:
    @pytest.mark.parametrize(
        ("a", "b"),
        [
            ("Home", "home"),
            ("Home", "HOME"),
            ("Stra\u00dfe", "STRASSE"),  # casefold, not lower()
            ("Home", FULLWIDTH_HOME),  # fullwidth look-alike
            ("Caf\u00e9", f"Cafe{COMBINING_ACUTE}"),
        ],
    )
    def test_equivalent_names_share_a_key(self, a: str, b: str) -> None:
        assert home_name_key(normalize_home_name(a)) == home_name_key(normalize_home_name(b))

    def test_different_names_have_different_keys(self) -> None:
        assert home_name_key("Home") != home_name_key("Home 2")

    def test_key_is_a_fixed_length_digest_without_the_name(self) -> None:
        """Casefolding/NFKC can expand text (U+FDFA -> 18 chars); a digest stays bounded."""
        long_name = "\ufdfa" * MAX_HOME_NAME_LENGTH

        key = home_name_key(long_name)

        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)
        assert "home" not in home_name_key("home")


class TestCurrency:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("USD", "USD"), ("usd", "USD"), ("eUr", "EUR"), (" jpy ", "JPY"), ("INR", "INR")],
    )
    def test_known_codes_are_accepted_and_uppercased(self, raw: str, expected: str) -> None:
        assert normalize_currency(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "US",
            "USDD",
            "XYZ",  # well-formed but not ISO 4217
            "XXX",  # "no currency"
            "XTS",  # testing code
            "XAU",  # gold, not a currency for a home
            "\u00dcSD",
            "U$D",
            "usd\x00",
            "HRK",  # withdrawn (Croatia adopted the euro)
        ],
    )
    def test_unknown_or_malformed_codes_are_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidCurrencyError):
            normalize_currency(raw)
