"""One canonical form per mailbox, matching the database's lowercase CHECK exactly."""

from email_validator import EmailNotValidError, validate_email

MAX_EMAIL_LENGTH = 320
MAX_LOCAL_PART_LENGTH = 64  # RFC 5321 4.5.3.1.1; email-validator does not enforce it


class InvalidEmailError(ValueError):
    def __init__(self) -> None:
        super().__init__("invalid email address")


def normalize_email(raw: str) -> str:
    """Lowercase, ASCII (IDNA) domain, ASCII local part.

    - Local parts are lowercased: providers treat them case-insensitively in practice, and two
      accounts differing only by case invite account confusion.
    - Unicode and punycode spellings of a domain collapse to the punycode form.
    - Non-ASCII local parts are rejected: Python's and PostgreSQL's lower() disagree on some of
      them (e.g. Turkish dotted I), which would break the database's lowercase CHECK.
    """
    candidate = raw.strip()
    if len(candidate) > MAX_EMAIL_LENGTH:
        raise InvalidEmailError
    try:
        parsed = validate_email(candidate, check_deliverability=False)
    except EmailNotValidError:
        raise InvalidEmailError from None
    if (
        not parsed.local_part.isascii()
        or len(parsed.local_part) > MAX_LOCAL_PART_LENGTH
        or parsed.ascii_domain is None
    ):
        raise InvalidEmailError
    normalized = f"{parsed.local_part}@{parsed.ascii_domain}".lower()
    if len(normalized) > MAX_EMAIL_LENGTH:
        raise InvalidEmailError
    return normalized
