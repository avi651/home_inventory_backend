from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import Depends, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clock import Clock
from app.core.config import Settings
from app.core.database import get_db_session
from app.core.passwords import PasswordHasher
from app.core.rate_limit import AuthRateLimits, RateLimit, RateLimiter
from app.core.tokens import AccessTokenClaims, AccessTokenService, InvalidTokenError
from app.exceptions.errors import (
    AuthenticationRequiredError,
    ProviderNotConfiguredError,
    RateLimitedError,
)
from app.services.auth_service import AuthService
from app.services.google_oauth import GoogleOAuthClient
from app.services.google_sign_in_service import GoogleSignInService
from app.services.session_service import Principal, SessionService

DbSession = Annotated[AsyncSession, Depends(get_db_session)]

# Documents the scheme in OpenAPI only; the header is parsed strictly below.
_bearer_scheme = HTTPBearer(auto_error=False)


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_clock(request: Request) -> Clock:
    clock: Clock = request.app.state.clock
    return clock


def get_access_tokens(request: Request) -> AccessTokenService:
    service: AccessTokenService = request.app.state.access_tokens
    return service


def get_password_hasher(request: Request) -> PasswordHasher:
    hasher: PasswordHasher | None = request.app.state.password_hasher
    if hasher is None:
        hasher = request.app.state.password_hasher = PasswordHasher()
    return hasher


def get_session_service(
    db: DbSession,
    access_tokens: Annotated[AccessTokenService, Depends(get_access_tokens)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
    clock: Annotated[Clock, Depends(get_clock)],
) -> SessionService:
    return SessionService(db, access_tokens, settings, clock=clock)


SessionServiceDep = Annotated[SessionService, Depends(get_session_service)]


def get_auth_service(
    request: Request,
    db: DbSession,
    sessions: SessionServiceDep,
    hasher: Annotated[PasswordHasher, Depends(get_password_hasher)],
    clock: Annotated[Clock, Depends(get_clock)],
) -> AuthService:
    return AuthService(
        db,
        hasher=hasher,
        sessions=sessions,
        rate_limiter=request.app.state.rate_limiter,
        rate_limits=request.app.state.rate_limits,
        clock=clock,
    )


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


def get_google_sign_in_service(
    request: Request,
    db: DbSession,
    sessions: SessionServiceDep,
    clock: Annotated[Clock, Depends(get_clock)],
) -> GoogleSignInService:
    google: GoogleOAuthClient | None = request.app.state.google_oauth
    if google is None:
        raise ProviderNotConfiguredError
    return GoogleSignInService(db, google=google, sessions=sessions, clock=clock)


GoogleSignInServiceDep = Annotated[GoogleSignInService, Depends(get_google_sign_in_service)]


def _bearer_token(request: Request) -> str:
    """Exactly one `Authorization: Bearer <token>` header; anything else is rejected.

    Never reads tokens from query strings or cookies.
    """
    headers = request.headers.getlist("authorization")
    if len(headers) != 1:
        raise AuthenticationRequiredError
    parts = headers[0].split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise AuthenticationRequiredError
    return parts[1]


async def get_access_claims(
    request: Request,
    access_tokens: Annotated[AccessTokenService, Depends(get_access_tokens)],
    _: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer_scheme)],
) -> AccessTokenClaims:
    """A validly signed, unexpired access token. Does NOT check session state (see below)."""
    try:
        return access_tokens.decode(_bearer_token(request))
    except InvalidTokenError:
        raise AuthenticationRequiredError from None


AccessClaims = Annotated[AccessTokenClaims, Depends(get_access_claims)]


async def get_current_principal(claims: AccessClaims, sessions: SessionServiceDep) -> Principal:
    """Token + live session owned by that user + active user. Use for every protected endpoint."""
    principal = await sessions.get_active_principal(
        user_id=claims.user_id, session_id=claims.session_id
    )
    if principal is None:
        raise AuthenticationRequiredError
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]


def _client_ip(request: Request) -> str:
    # X-Forwarded-For is never read here: uvicorn --proxy-headers --forwarded-allow-ips=<LB>
    # rewrites request.client only for trusted proxies.
    return request.client.host if request.client else "unknown"


def rate_limited(rule_name: str) -> Any:
    """Per-client-IP limit for one of AuthRateLimits' rules, e.g. "login_per_ip"."""

    async def dependency(request: Request) -> None:
        limits: AuthRateLimits = request.app.state.rate_limits
        rule: RateLimit = getattr(limits, rule_name)
        limiter: RateLimiter = request.app.state.rate_limiter
        result = await limiter.hit(f"{rule_name}:{_client_ip(request)}", rule)
        if not result.allowed:
            raise RateLimitedError(result.retry_after)

    check: Callable[[Request], Awaitable[None]] = dependency
    return Depends(check)
