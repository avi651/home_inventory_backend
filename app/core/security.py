from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Environment, Settings

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
