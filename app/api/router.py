from fastapi import APIRouter

from app.api.dependencies import oauth_service
from app.api.routes import auth
from app.api.routes.oauth import provider_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(provider_router("google", oauth_service("google_oauth")))
api_router.include_router(provider_router("apple", oauth_service("apple_oauth")))
