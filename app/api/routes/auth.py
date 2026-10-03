from fastapi import APIRouter, Response, status

from app.api.dependencies import (
    AccessClaims,
    AuthServiceDep,
    CurrentPrincipal,
    SessionServiceDep,
    rate_limited,
)
from app.models.auth_session import SessionRevokeReason
from app.schemas.auth import (
    AuthResponse,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.user import UserRead

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=AuthResponse,
    dependencies=[rate_limited("register_per_ip")],
)
async def register(body: RegisterRequest, auth: AuthServiceDep) -> AuthResponse:
    user, pair = await auth.register(body.email, body.password.get_secret_value())
    return AuthResponse.build(user, pair)


@router.post(
    "/login",
    response_model=AuthResponse,
    dependencies=[rate_limited("login_per_ip")],
)
async def login(body: LoginRequest, auth: AuthServiceDep) -> AuthResponse:
    user, pair = await auth.login(body.email, body.password.get_secret_value())
    return AuthResponse.build(user, pair)


@router.post(
    "/guest",
    status_code=status.HTTP_201_CREATED,
    response_model=AuthResponse,
    dependencies=[rate_limited("guest_per_ip")],
)
async def guest(auth: AuthServiceDep) -> AuthResponse:
    """Always a new guest user: takes no input, so a client cannot choose who it becomes."""
    user, pair = await auth.sign_in_as_guest()
    return AuthResponse.build(user, pair)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[rate_limited("refresh_per_ip")],
)
async def refresh(body: RefreshRequest, sessions: SessionServiceDep) -> TokenResponse:
    return TokenResponse.from_pair(await sessions.refresh(body.refresh_token.get_secret_value()))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(claims: AccessClaims, sessions: SessionServiceDep) -> Response:
    """Ends the current session. Idempotent: an already-revoked session still gets 204."""
    await sessions.revoke(
        user_id=claims.user_id, session_id=claims.session_id, reason=SessionRevokeReason.LOGOUT
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(principal: CurrentPrincipal, sessions: SessionServiceDep) -> Response:
    await sessions.revoke(user_id=principal.user.id, reason=SessionRevokeReason.LOGOUT_ALL)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserRead)
async def me(principal: CurrentPrincipal) -> UserRead:
    return UserRead.from_user(principal.user)
