"""Room name rules (unit): the Homes normalization and name-key conventions, room-specific errors.

Invisible and look-alike characters are written as escapes so the source stays readable.
"""

import pytest

from app.core.home_fields import home_name_key, normalize_home_name
from app.core.room_fields import (
    MAX_ROOM_NAME_LENGTH,
    InvalidRoomNameError,
    normalize_room_name,
    room_name_key,
)

NBSP, EM_SPACE = "\u00a0", "\u2003"
FULLWIDTH_KITCHEN = "\uff2b\uff29\uff34\uff23\uff28\uff25\uff2e"
COMBINING_ACUTE = "\u0301"


def test_max_room_name_length_is_100() -> None:
    assert MAX_ROOM_NAME_LENGTH == 100


class TestName:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Kitchen", "Kitchen"),
            ("  Living Room  ", "Living Room"),
            (f"Master   Bed{NBSP}room", "Master Bed room"),  # internal runs (incl. NBSP) collapse
            ("K\u00fcche", "K\u00fcche"),
            ("\u53f0\u6240", "\u53f0\u6240"),
            ("\U0001f6cf Guest", "\U0001f6cf Guest"),
            (f"Cafe{COMBINING_ACUTE}", "Caf\u00e9"),  # NFC: combining accent composed
        ],
    )
    def test_valid_names_are_normalized(self, raw: str, expected: str) -> None:
        assert normalize_room_name(raw) == expected

    def test_max_length_is_inclusive(self) -> None:
        name = "a" * MAX_ROOM_NAME_LENGTH

        assert normalize_room_name(name) == name

    def test_length_is_counted_after_trimming(self) -> None:
        assert normalize_room_name(f"  {'a' * MAX_ROOM_NAME_LENGTH}  ") == "a" * 100

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            NBSP + EM_SPACE,
            "a" * (MAX_ROOM_NAME_LENGTH + 1),
            "line\nbreak",
            "tab\there",
            "nul\x00byte",
            "bidi\u202enehctiK",  # right-to-left override (spoofing)
            "zero\u200bwidth",
            "joiner\u200dhidden",
            "para\u2029sep",
            "private\ue000use",
            "unassigned\U000e0080x",
        ],
    )
    def test_invalid_names_are_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidRoomNameError):
            normalize_room_name(raw)

    def test_oversized_input_is_rejected_before_normalization_work(self) -> None:
        with pytest.raises(InvalidRoomNameError):
            normalize_room_name("a" * 1_000_000)

    def test_error_is_a_value_error_with_a_fixed_room_message(self) -> None:
        with pytest.raises(InvalidRoomNameError) as exc_info:
            normalize_room_name("secret\x00name")

        assert isinstance(exc_info.value, ValueError)
        assert str(exc_info.value) == "invalid room name"
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__

    @pytest.mark.parametrize(
        "raw", ["  Kitchen ", f"Bed{NBSP}room", f"Cafe{COMBINING_ACUTE}", "\U0001f6cf"]
    )
    def test_matches_the_homes_normalization_convention(self, raw: str) -> None:
        assert normalize_room_name(raw) == normalize_home_name(raw)


class TestNameKey:
    @pytest.mark.parametrize(
        ("a", "b"),
        [
            ("Kitchen", "kitchen"),
            ("Kitchen", "KITCHEN"),
            ("Stra\u00dfe", "STRASSE"),  # casefold, not lower()
            ("Kitchen", FULLWIDTH_KITCHEN),  # fullwidth look-alike
            ("Caf\u00e9", f"Cafe{COMBINING_ACUTE}"),
            ("  Living   Room ", "living room"),
        ],
    )
    def test_equivalent_names_share_a_key(self, a: str, b: str) -> None:
        assert room_name_key(normalize_room_name(a)) == room_name_key(normalize_room_name(b))

    def test_different_names_have_different_keys(self) -> None:
        assert room_name_key("Kitchen") != room_name_key("Kitchen 2")

    def test_key_is_a_fixed_length_digest_without_the_name(self) -> None:
        """Casefolding/NFKC can expand text (U+FDFA -> 18 chars); a digest stays bounded."""
        key = room_name_key("\ufdfa" * MAX_ROOM_NAME_LENGTH)

        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)
        assert "kitchen" not in room_name_key("kitchen")

    @pytest.mark.parametrize("name", ["Kitchen", "Stra\u00dfe", FULLWIDTH_KITCHEN])
    def test_matches_the_homes_key_convention(self, name: str) -> None:
        assert room_name_key(name) == home_name_key(name)
