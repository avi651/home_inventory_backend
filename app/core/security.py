from collections.abc import Sequence

from starlette.datastructures import MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Environment, Settings

MAX_REQUEST_BODY_BYTES = 1024 * 1024
HSTS_VALUE = "max-age=63072000; includeSubDomains"
API_CSP = "default-src 'none'; frame-ancestors 'none'"


def security_headers(settings: Settings, *, include_csp: bool = True) -> dict[str, str]:
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }
    if include_csp:
        headers["Content-Security-Policy"] = API_CSP
    if settings.environment is Environment.PRODUCTION:
        headers["Strict-Transport-Security"] = HSTS_VALUE
    return headers


class SecurityHeadersMiddleware:
    """Pure ASGI middleware adding security headers without overriding route-set values."""

    def __init__(self, app: ASGIApp, settings: Settings, csp_exempt_paths: frozenset[str]) -> None:
        self.app = app
        self.settings = settings
        self.csp_exempt_paths = csp_exempt_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Swagger UI/ReDoc (non-production only) need scripts from a CDN.
        include_csp = scope["path"] not in self.csp_exempt_paths
        extra = security_headers(self.settings, include_csp=include_csp)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in extra.items():
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _error(code: str, message: str) -> JSONResponse:
    # Same envelope as the exception handlers; fixed text, nothing from the request echoed.
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=400)


# Exactly one acceptable scheme per scope type ("wss" on an HTTP request is not HTTPS).
_SECURE_SCHEMES = {"http": "https", "websocket": "wss"}


class HTTPSOnlyMiddleware:
    """Rejects (never redirects) plain-HTTP requests, except the exact probe paths.

    Trusts only scope["scheme"]. Behind the load balancer that is set by uvicorn's
    --proxy-headers from X-Forwarded-Proto, and only for peers in --forwarded-allow-ips; this
    middleware never reads forwarded headers itself. Rejecting instead of redirecting means a
    misconfigured proxy fails closed with a 400 rather than looping, and a token sent over
    HTTP is refused rather than silently honoured.
    """

    def __init__(self, app: ASGIApp, exempt_paths: frozenset[str]) -> None:
        self.app = app
        self.exempt_paths = exempt_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        secure_scheme = _SECURE_SCHEMES.get(scope["type"])
        if (
            secure_scheme is not None
            and scope["scheme"] != secure_scheme
            and scope["path"] not in self.exempt_paths
        ):
            await _error("https_required", "HTTPS is required")(scope, receive, send)
            return
        await self.app(scope, receive, send)


class TrustedHostGuard:
    """Starlette's TrustedHostMiddleware with the API error envelope and probe-path exemption.

    Matching (Host header only, port ignored) is Starlette's; X-Forwarded-Host is never used.
    Probes are exempt because health checks address an instance by IP and their responses do
    not depend on Host.
    """

    _VALIDATED = "home_inventory.host_validated"

    def __init__(
        self, app: ASGIApp, allowed_hosts: Sequence[str], exempt_paths: frozenset[str]
    ) -> None:
        self.app = app
        self.exempt_paths = exempt_paths
        self._checker = TrustedHostMiddleware(
            self._mark_validated, allowed_hosts=allowed_hosts, www_redirect=False
        )

    async def _mark_validated(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope[self._VALIDATED] = True

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or scope["path"] in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        # Starlette answers a bad host itself (plain text); swallow that answer and send ours.
        async def discard(_: Message) -> None:
            return None

        await self._checker(scope, receive, discard)
        if not scope.pop(self._VALIDATED, False):
            await _error("invalid_host", "Invalid host")(scope, receive, send)
            return
        await self.app(scope, receive, send)


class _BodyTooLargeError(Exception):
    pass


class RequestBodyLimitMiddleware:
    """Refuses request bodies over `max_bytes` with 413, before auth, parsing or the database.

    A declared Content-Length over the limit is refused without reading anything. Bodies
    without one (chunked) are counted while streamed and cut off at the limit, so leaving the
    header out does not get around it. Routes needing larger bodies (future uploads) will need
    their own, explicit limit.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _content_length(scope)
        if declared is not None and declared > self.max_bytes:
            await _too_large(scope, receive, send)
            return

        received = 0
        response_started = False

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _BodyTooLargeError:
            if response_started:  # pragma: no cover - apps read the body before responding
                raise
            await _too_large(scope, receive, send)


def _content_length(scope: Scope) -> int | None:
    for name, value in scope["headers"]:
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _too_large(scope: Scope, receive: Receive, send: Send) -> None:
    body = {"error": {"code": "payload_too_large", "message": "Request body too large"}}
    await JSONResponse(body, status_code=413)(scope, receive, send)
