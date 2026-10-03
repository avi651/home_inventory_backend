"""Import every model here so Alembic autogenerate sees the full metadata."""

from app.models.auth_session import AuthSession, SessionRevokeReason
from app.models.base import Base
from app.models.refresh_token import RefreshToken
from app.models.user import AuthProvider, User

__all__ = ["AuthProvider", "AuthSession", "Base", "RefreshToken", "SessionRevokeReason", "User"]
