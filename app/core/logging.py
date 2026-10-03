import logging
import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"
DEFAULT_LOGGERS = ("", "uvicorn", "uvicorn.error", "uvicorn.access")

_SENSITIVE_KEY = (
    r"[a-z_-]*password|passwd|pwd|[a-z_-]*token|[a-z_-]*secret|api[_-]?key"
    r"|authorization|set-cookie|cookie"
)
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # scheme://user:password@host  ->  scheme://user:[REDACTED]@host
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/\s@]+:)[^@\s]+(@)", re.I), rf"\1{REDACTED}\2"),
    # key=value, key: value, "key": "value"  (optionally "Bearer <value>")
    (
        re.compile(
            rf"""(["']?\b(?:{_SENSITIVE_KEY})\b["']?\s*[:=]\s*(?:(?:bearer|basic)\s+)?)"""
            r"""(?:"[^"]*"|'[^']*'|[^\s&,;}"']+)""",
            re.I,
        ),
        rf"\1{REDACTED}",
    ),
    (re.compile(r"\b(bearer)\s+[A-Za-z0-9._~+/=-]+", re.I), rf"\1 {REDACTED}"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), REDACTED),
)


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    """Masks secrets in log output. Never drops records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        message = record.getMessage()
        redacted = redact(message)
        if redacted != message:
            # The secret spans template and args (e.g. "password=%s"); collapse to final text.
            record.msg, record.args = redacted, None

        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True


def install_log_redaction(logger_names: Iterable[str] = DEFAULT_LOGGERS) -> None:
    """Attach the filter to handlers: logger-level filters skip propagated records."""
    for name in logger_names:
        for handler in logging.getLogger(name).handlers:
            if not any(isinstance(f, RedactingFilter) for f in handler.filters):
                handler.addFilter(RedactingFilter())
