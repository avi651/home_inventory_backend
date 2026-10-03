"""Import every model here so Alembic autogenerate sees the full metadata."""

from app.models.auth_session import AuthSession, SessionRevokeReason
from app.models.base import Base
from app.models.home import Home
from app.models.oauth_login_attempt import OAuthLoginAttempt
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.user_identity import IdentityProvider, UserIdentity

__all__ = [
    "AuthSession",
    "Base",
    "Home",
    "IdentityProvider",
    "OAuthLoginAttempt",
    "RefreshToken",
    "SessionRevokeReason",
    "User",
    "UserIdentity",
]
