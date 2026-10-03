import pytest

from app.core.emails import InvalidEmailError, normalize_email


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("alice@example.com", "alice@example.com"),
        ("Alice@Example.COM", "alice@example.com"),
        ("  bob@x.io  ", "bob@x.io"),
        ("a.b+tag@sub.example.org", "a.b+tag@sub.example.org"),
        # Unicode and punycode spellings of one domain must map to a single canonical form.
        ("a@bücher.example", "a@xn--bcher-kva.example"),
        ("a@xn--bcher-kva.example", "a@xn--bcher-kva.example"),
        ("A@BÜCHER.example", "a@xn--bcher-kva.example"),
    ],
)
def test_normalizes_to_canonical_ascii(raw: str, expected: str) -> None:
    assert normalize_email(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not-an-email",
        "@example.com",
        "alice@",
        "alice@@example.com",
        "Alice <alice@example.com>",
        "İ@example.com",  # non-ASCII local part: Python and PostgreSQL lower() disagree
        "ä@example.com",
        "a" * 65 + "@example.com",  # local part > 64
        "a@" + "b" * 250 + ".com",
        "alice\n@example.com",  # embedded control character (header-injection shape)
        "alice@exa mple.com",
    ],
)
def test_rejects_invalid_or_unsupported(raw: str) -> None:
    with pytest.raises(InvalidEmailError):
        normalize_email(raw)


def test_error_does_not_echo_input() -> None:
    with pytest.raises(InvalidEmailError) as exc_info:
        normalize_email("secret-person@@example.com")

    assert "secret-person" not in str(exc_info.value)


def test_result_is_lowercase_ascii_like_the_database_requires() -> None:
    result = normalize_email("MiXeD.Case@Example.ORG")

    assert result.isascii()
    assert result == result.lower()
