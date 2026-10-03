from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.core.emails import MAX_EMAIL_LENGTH, InvalidEmailError, normalize_email
from app.core.password_policy import MAX_PASSWORD_LENGTH
from app.models.user import User
from app.schemas.user import UserRead
from app.services.session_service import TokenPair

# Requests: unknown fields rejected (no client-chosen ids/flags); raw input never echoed in errors.
_REQUEST_CONFIG = ConfigDict(extra="forbid", hide_input_in_errors=True)


class _Credentials(BaseModel):
    model_config = _REQUEST_CONFIG

    email: str = Field(max_length=MAX_EMAIL_LENGTH)
    # Bounded here so oversized input is rejected before any hashing work.
    password: SecretStr = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("email")
    @classmethod
    def _normalize(cls, value: str) -> str:
        try:
            return normalize_email(value)
        except InvalidEmailError:
            raise ValueError("invalid email address") from None


class RegisterRequest(_Credentials):
    pass


class LoginRequest(_Credentials):
    pass


class RefreshRequest(BaseModel):
    model_config = _REQUEST_CONFIG

    refresh_token: SecretStr = Field(min_length=1, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type label
    expires_in: int

    @classmethod
    def from_pair(cls, pair: TokenPair) -> Self:
        return cls(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            expires_in=pair.expires_in,
        )


class AuthResponse(TokenResponse):
    user: UserRead

    @classmethod
    def build(cls, user: User, pair: TokenPair) -> AuthResponse:
        return cls(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            expires_in=pair.expires_in,
            user=UserRead.model_validate(user),
        )
