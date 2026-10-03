import io
import logging
from collections.abc import Iterator

import pytest

from app.core.config import Settings
from app.core.logging import REDACTED, RedactingFilter, install_log_redaction, redact
from app.main import create_app

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl"


class TestRedact:
    @pytest.mark.parametrize(
        ("text", "secret"),
        [
            ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
            ("authorization=Bearer s3cr3t-token", "s3cr3t-token"),
            ("password=hunter2", "hunter2"),
            ("password: hunter2", "hunter2"),
            ('{"password": "hunter2"}', "hunter2"),
            ("{'new_password': 'hunter2'}", "hunter2"),
            ("GET /reset?token=abc123XYZ&x=1", "abc123XYZ"),
            ('{"refresh_token": "rt-value"}', "rt-value"),
            ("access_token=at-value", "at-value"),
            ("JWT_SECRET=supersecretvalue", "supersecretvalue"),
            ("api_key=key-123", "key-123"),
            ("Cookie: session=abc", "session=abc"),
            ("postgresql+psycopg://app:dbpass@localhost/db", "dbpass"),
            (f"decoded {JWT} ok", JWT),
        ],
    )
    def test_masks_sensitive_values(self, text: str, secret: str) -> None:
        result = redact(text)

        assert secret not in result
        assert REDACTED in result

    def test_leaves_ordinary_text_alone(self) -> None:
        text = "GET /health 200 in 3ms for item 'Sony TV'"

        assert redact(text) == text

    def test_keeps_key_name_for_debuggability(self) -> None:
        assert redact("password=hunter2") == f"password={REDACTED}"


@pytest.fixture
def captured() -> Iterator[tuple[logging.Logger, io.StringIO]]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    logger = logging.getLogger("tests.redaction")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    yield logger, stream
    logger.removeHandler(handler)


class TestRedactingFilter:
    def test_redacts_interpolated_args(self, captured: tuple[logging.Logger, io.StringIO]) -> None:
        logger, stream = captured

        logger.info("login attempt password=%s", "hunter2")

        assert "hunter2" not in stream.getvalue()
        assert "login attempt" in stream.getvalue()

    def test_redacts_exception_tracebacks(
        self, captured: tuple[logging.Logger, io.StringIO]
    ) -> None:
        logger, stream = captured

        try:
            raise ValueError(f"bad token {JWT}")
        except ValueError:
            logger.exception("request failed")

        output = stream.getvalue()
        assert JWT not in output
        assert "ValueError" in output

    def test_preserves_args_tuple_for_formatters_that_need_it(self) -> None:
        # uvicorn's AccessFormatter reads record.args positionally.
        record = logging.LogRecord(
            "uvicorn.access", logging.INFO, __file__, 1,
            '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:5000", "GET", "/reset?token=abc123XYZ", "1.1", 200),
            None,
        )  # fmt: skip

        RedactingFilter().filter(record)

        assert isinstance(record.args, tuple)
        assert record.args[2] == f"/reset?token={REDACTED}"
        assert record.args[4] == 200

    def test_never_drops_records(self, captured: tuple[logging.Logger, io.StringIO]) -> None:
        logger, stream = captured

        logger.warning("plain message")

        assert "plain message" in stream.getvalue()


class TestInstall:
    def test_attaches_filter_to_handlers_once(self) -> None:
        logger = logging.getLogger("tests.install")
        handler = logging.StreamHandler(io.StringIO())
        logger.addHandler(handler)
        try:
            install_log_redaction(["tests.install"])
            install_log_redaction(["tests.install"])

            redacting = [f for f in handler.filters if isinstance(f, RedactingFilter)]
            assert len(redacting) == 1
        finally:
            logger.removeHandler(handler)

    def test_create_app_installs_redaction_on_uvicorn_handlers(
        self, test_settings: Settings
    ) -> None:
        handler = logging.StreamHandler(io.StringIO())
        logging.getLogger("uvicorn.access").addHandler(handler)
        try:
            create_app(test_settings)

            assert any(isinstance(f, RedactingFilter) for f in handler.filters)
        finally:
            logging.getLogger("uvicorn.access").removeHandler(handler)
