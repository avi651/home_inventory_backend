import uuid
from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict

from app.models.user import User
from app.models.user_identity import IdentityProvider, UserIdentity


class UserRead(BaseModel):
    """The only user shape the API returns. Deliberately has no credential or subject fields.

    Keeps the pre-D1 shape: `email`/`auth_provider` describe the user's primary identity
    (the email login if linked, else the first linked identity; "guest" when there is none).
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    email: str | None
    auth_provider: Literal["email", "google", "apple", "guest"]
    is_active: bool
    created_at: datetime

    @classmethod
    def from_user(cls, user: User) -> Self:
        """`user.identities` must be loaded (it is never lazy-loaded)."""
        primary = _primary_identity(user.identities)
        return cls(
            id=user.id,
            email=primary.email if primary else None,
            auth_provider=primary.provider.value if primary else "guest",
            is_active=user.is_active,
            created_at=user.created_at,
        )


def _primary_identity(identities: list[UserIdentity]) -> UserIdentity | None:
    for identity in identities:
        if identity.provider is IdentityProvider.EMAIL:
            return identity
    return identities[0] if identities else None
