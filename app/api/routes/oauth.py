"""Provider sign-in endpoints, one identical pair per provider: /auth/{provider}/start|callback."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import OAuthServiceFactory, rate_limited
from app.schemas.auth import AuthResponse
from app.schemas.oauth import OAuthCallbackRequest, OAuthStartResponse
from app.services.oauth_sign_in_service import OAuthSignInService


def provider_router(name: str, get_service: OAuthServiceFactory) -> APIRouter:
    router = APIRouter(prefix=f"/auth/{name}", tags=["auth"])
    service_dep = Annotated[OAuthSignInService, Depends(get_service)]

    @router.post(
        "/start",
        response_model=OAuthStartResponse,
        dependencies=[rate_limited("oauth_start_per_ip")],
        name=f"{name}_start",
    )
    async def start(service: service_dep) -> OAuthStartResponse:
        """POST, not GET: it creates server-side state and returns a secret binding token, so
        it must not be cacheable, prefetchable or triggerable by a cross-site link."""
        return OAuthStartResponse.from_start(await service.start())

    @router.post(
        "/callback",
        response_model=AuthResponse,
        dependencies=[rate_limited("oauth_callback_per_ip")],
        name=f"{name}_callback",
    )
    async def callback(body: OAuthCallbackRequest, service: service_dep) -> AuthResponse:
        """The client forwards `code` and `state` from the provider redirect in the body (never
        the URL, so they stay out of access logs) together with its `attempt_token`."""
        user, pair = await service.complete(
            code=body.code.get_secret_value(),
            state=body.state.get_secret_value(),
            attempt_token=body.attempt_token.get_secret_value(),
        )
        return AuthResponse.build(user, pair)

    return router
