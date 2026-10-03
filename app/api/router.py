from fastapi import APIRouter

from app.api.routes import auth, google_auth

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(google_auth.router)
