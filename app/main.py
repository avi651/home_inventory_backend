from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import health
from app.core.config import Settings, get_settings
from app.core.security import SecurityHeadersMiddleware
from app.exceptions.handlers import register_exception_handlers

DOCS_URL, REDOC_URL, OPENAPI_URL = "/docs", "/redoc", "/openapi.json"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory. Run with: uvicorn app.main:create_app --factory"""
    settings = settings or get_settings()
    docs = settings.docs_enabled

    app = FastAPI(
        title="Home Inventory AI",
        version="1.0.0",
        debug=settings.debug,
        docs_url=DOCS_URL if docs else None,
        redoc_url=REDOC_URL if docs else None,
        openapi_url=OPENAPI_URL if docs else None,
    )
    app.state.settings = settings

    register_exception_handlers(app, settings)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=600,
        )
    # Added last so it is outermost and also covers CORS preflight responses.
    app.add_middleware(
        SecurityHeadersMiddleware,
        settings=settings,
        csp_exempt_paths=frozenset({DOCS_URL, REDOC_URL}) if docs else frozenset(),
    )

    app.include_router(health.router)
    return app
