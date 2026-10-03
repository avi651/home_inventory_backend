from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import Settings
from app.core.security import security_headers

ERROR_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    422: "validation_error",
    429: "too_many_requests",
    500: "internal_error",
}


def error_body(status_code: int, **extra: Any) -> dict[str, Any]:
    code = ERROR_CODES.get(status_code, "http_error")
    message = HTTPStatus(status_code).phrase.capitalize()
    return {"error": {"code": code, "message": message, **extra}}


def _safe_validation_details(exc: RequestValidationError) -> list[dict[str, Any]]:
    # Deliberately omit "input" and "ctx": they can echo passwords or other submitted data.
    return [
        {"loc": list(err["loc"]), "msg": err["msg"], "type": err["type"]} for err in exc.errors()
    ]


def register_exception_handlers(app: FastAPI, settings: Settings) -> None:
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Messages come from the status phrase, never from exc.detail, so nothing internal leaks.
        return JSONResponse(error_body(exc.status_code), exc.status_code, headers=exc.headers)

    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(error_body(422, details=_safe_validation_details(exc)), 422)

    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Runs in Starlette's outermost ServerErrorMiddleware, outside SecurityHeadersMiddleware,
        # so headers are attached here. The exception is re-raised by Starlette and logged
        # server-side by the ASGI server; the client only sees the generic body.
        return JSONResponse(error_body(500), 500, headers=security_headers(settings))

    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)
