import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.user import AuthProvider


class UserRead(BaseModel):
    """The only user shape the API returns. Deliberately has no credential fields."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    email: str | None
    auth_provider: AuthProvider
    is_active: bool
    created_at: datetime
