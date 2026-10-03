from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.api.routes import health
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.core.database import create_db_engine, create_session_factory
from app.core.logging import install_log_redaction
from app.core.rate_limit import DEFAULT_AUTH_RATE_LIMITS, InMemoryRateLimiter
from app.core.security import HTTPSOnlyMiddleware, SecurityHeadersMiddleware, TrustedHostGuard
from app.core.tokens import AccessTokenService
from app.exceptions.handlers import register_exception_handlers
from app.services.apple_oauth import AppleOAuthClient, AppleOAuthConfig
from app.services.google_oauth import GoogleOAuthClient, GoogleOAuthConfig

DOCS_URL, REDOC_URL, OPENAPI_URL = "/docs", "/redoc", "/openapi.json"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory. Run with: uvicorn app.main:create_app --factory"""
    settings = settings or get_settings()
    install_log_redaction()
    docs = settings.docs_enabled
    engine = create_db_engine(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        for provider in (app.state.google_oauth, app.state.apple_oauth):
            if provider is not None:
                await provider.aclose()
        await engine.dispose()

    app = FastAPI(
        title="Home Inventory AI",
        version="1.0.0",
        debug=settings.debug,
        docs_url=DOCS_URL if docs else None,
        redoc_url=REDOC_URL if docs else None,
        openapi_url=OPENAPI_URL if docs else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    # Swappable as a whole in tests; components read it at call time, never capture a value.
    app.state.clock = utc_now
    app.state.access_tokens = AccessTokenService(settings, clock=lambda: app.state.clock())
    app.state.rate_limiter = InMemoryRateLimiter(clock=lambda: app.state.clock())
    app.state.rate_limits = DEFAULT_AUTH_RATE_LIMITS
    # Created lazily on first use (its constructor runs one Argon2 hash).
    app.state.password_hasher = None
    # Absent unless configured: that provider's endpoints answer 404 and the API still starts.
    app.state.google_oauth = (
        GoogleOAuthClient(
            GoogleOAuthConfig.from_settings(settings),
            httpx.AsyncClient(follow_redirects=False),
            clock=lambda: app.state.clock(),
        )
        if settings.google_oauth_enabled
        else None
    )
    app.state.apple_oauth = (
        AppleOAuthClient(
            AppleOAuthConfig.from_settings(settings),
            httpx.AsyncClient(follow_redirects=False),
            clock=lambda: app.state.clock(),
        )
        if settings.apple_oauth_enabled
        else None
    )

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
    # Transport checks run before CORS and routing, so a rejected request touches nothing.
    if settings.https_required:
        app.add_middleware(HTTPSOnlyMiddleware, exempt_paths=health.PROBE_PATHS)
    if settings.allowed_hosts:
        app.add_middleware(
            TrustedHostGuard,
            allowed_hosts=settings.allowed_hosts,
            exempt_paths=health.PROBE_PATHS,
        )
    # Added last so it is outermost and also covers CORS preflight and rejection responses.
    app.add_middleware(
        SecurityHeadersMiddleware,
        settings=settings,
        csp_exempt_paths=frozenset({DOCS_URL, REDOC_URL}) if docs else frozenset(),
    )

    app.include_router(health.router)
    app.include_router(api_router)
    return app
