import pytest

from app.core.password_policy import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordViolation,
    check_password,
)


def test_length_bounds_follow_nist_guidance() -> None:
    assert MIN_PASSWORD_LENGTH == 12
    assert MAX_PASSWORD_LENGTH >= 64


@pytest.mark.parametrize(
    "password",
    [
        "violet piano under the stairs",
        "Tr0ub4dor&3-extended",
        "пароль-очень-длинный",  # non-Latin passphrase
        "🏠📦🔑 my home inventory",
        "  leading and trailing spaces  ",  # spaces are allowed, not trimmed
        "k7#Qm2!vRw9p",  # exactly the minimum length
    ],
)
def test_strong_passwords_are_accepted(password: str) -> None:
    assert check_password(password, email="alice@example.com") == []


def test_minimum_length_is_inclusive() -> None:
    assert check_password("k7#Qm2!vRw9p") == []
    assert PasswordViolation.TOO_SHORT in check_password("k7#Qm2!vRw9")


def test_maximum_length_is_inclusive() -> None:
    at_limit = ("abcdefghij" * 20)[:MAX_PASSWORD_LENGTH]

    assert PasswordViolation.TOO_LONG not in check_password(at_limit)
    assert PasswordViolation.TOO_LONG in check_password(at_limit + "z")


def test_length_counts_characters_not_bytes() -> None:
    twelve_emoji = "🏠📦🔑🧰📺🚲🎸📚🪴🧸🎨🧩"  # 12 code points, 48 UTF-8 bytes
    assert len(twelve_emoji) == 12

    assert PasswordViolation.TOO_SHORT not in check_password(twelve_emoji)
    assert PasswordViolation.TOO_SHORT in check_password(twelve_emoji[:11])


@pytest.mark.parametrize(
    "password",
    [
        "password1234",
        "Password1234",
        "123456789012",
        "qwertyuiop12",
        "iloveyou1234",
        "correct horse battery staple",  # famous (xkcd) passphrases are in breach lists too
        "HomeInventory123",  # service-specific words (NIST 800-63B context words)
    ],
)
def test_common_passwords_are_rejected_case_insensitively(password: str) -> None:
    assert PasswordViolation.COMMON in check_password(password)


@pytest.mark.parametrize("password", ["aaaaaaaaaaaa", "111111111111111"])
def test_single_repeated_character_is_rejected(password: str) -> None:
    assert PasswordViolation.COMMON in check_password(password)


@pytest.mark.parametrize(
    "password", ["alice.smith-garden", "my-ALICE.SMITH-pass", "xxalice.smithxx99"]
)
def test_password_containing_email_local_part_is_rejected(password: str) -> None:
    violations = check_password(password, email="Alice.Smith@example.com")

    assert PasswordViolation.CONTAINS_EMAIL in violations


def test_short_email_local_part_is_not_matched() -> None:
    # "al@x.io": a 2-char local part would reject far too many legitimate passwords.
    assert check_password("total-algebra-2024", email="al@x.io") == []


def test_whitespace_only_is_rejected() -> None:
    assert PasswordViolation.BLANK in check_password(" " * 20)


@pytest.mark.parametrize("control", ["\x00", "\x1b", "​"])
def test_control_and_invisible_characters_are_rejected(control: str) -> None:
    assert PasswordViolation.INVALID_CHARACTERS in check_password(f"valid-pass{control}word")


def test_multiple_violations_are_all_reported() -> None:
    violations = check_password("alice\x00", email="alice@example.com")

    assert set(violations) >= {
        PasswordViolation.TOO_SHORT,
        PasswordViolation.INVALID_CHARACTERS,
    }


def test_violations_are_codes_that_never_contain_the_password() -> None:
    password = "alice-secret"

    for violation in check_password(password, email="alice@example.com"):
        assert password not in violation.value
        assert violation.value.isidentifier()
