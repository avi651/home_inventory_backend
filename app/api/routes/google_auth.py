from fastapi import APIRouter

from app.api.dependencies import GoogleSignInServiceDep, rate_limited
from app.schemas.auth import AuthResponse
from app.schemas.oauth import OAuthCallbackRequest, OAuthStartResponse

router = APIRouter(prefix="/auth/google", tags=["auth"])


@router.post(
    "/start",
    response_model=OAuthStartResponse,
    dependencies=[rate_limited("oauth_start_per_ip")],
)
async def start(google: GoogleSignInServiceDep) -> OAuthStartResponse:
    """POST, not GET: it creates server-side state and returns a secret binding token, so it
    must not be cacheable, prefetchable or triggerable by a cross-site link."""
    return OAuthStartResponse.from_start(await google.start())


@router.post(
    "/callback",
    response_model=AuthResponse,
    dependencies=[rate_limited("oauth_callback_per_ip")],
)
async def callback(body: OAuthCallbackRequest, google: GoogleSignInServiceDep) -> AuthResponse:
    """The client forwards `code` and `state` from Google's redirect in the body (never the URL,
    so they stay out of access logs) together with its `attempt_token` from /start."""
    user, pair = await google.complete(
        code=body.code.get_secret_value(),
        state=body.state.get_secret_value(),
        attempt_token=body.attempt_token.get_secret_value(),
    )
    return AuthResponse.build(user, pair)
