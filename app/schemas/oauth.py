from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.services.oauth_sign_in_service import OAuthStart


class OAuthStartResponse(BaseModel):
    authorization_url: str
    attempt_token: str
    expires_in: int

    @classmethod
    def from_start(cls, start: OAuthStart) -> OAuthStartResponse:
        return cls(
            authorization_url=start.authorization_url,
            attempt_token=start.attempt_token,
            expires_in=start.expires_in,
        )


class OAuthCallbackRequest(BaseModel):
    """Only what the provider redirect carried plus the client's binding token.

    Identity data (sub, email, ID tokens) is never accepted from the client: unknown fields
    are rejected, and the identity comes only from the server-side code exchange.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    code: SecretStr = Field(min_length=1, max_length=2048)
    state: SecretStr = Field(min_length=1, max_length=512)
    attempt_token: SecretStr = Field(min_length=1, max_length=512)
