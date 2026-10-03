import re
from enum import StrEnum
from functools import lru_cache
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.apple_keys import load_apple_private_key

MIN_JWT_SECRET_LENGTH = 32
MIN_JWT_SECRET_DISTINCT_CHARS = 10
PLACEHOLDER_MARKERS = ("changeme", "change-me", "placeholder", "example", "generate", "<", ">")
REQUIRED_DB_SCHEME = "postgresql+psycopg://"
# A bare lowercase hostname or IP (optionally a "*.domain" pattern): no scheme, port or path.
_APPLE_ID = re.compile(r"[A-Z0-9]{10}")
_APPLE_CLIENT_ID = re.compile(r"[A-Za-z0-9.-]{1,255}")
_ALLOWED_HOST = re.compile(r"(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?")


class Environment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        # Never echo raw input (secrets, DSNs) inside validation errors.
        hide_input_in_errors=True,
    )

    environment: Environment = Environment.LOCAL
    debug: bool = False

    database_url: SecretStr
    migration_database_url: SecretStr

    jwt_secret: SecretStr
    # Symmetric HMAC only; "none" and asymmetric algorithms are rejected outright.
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_expire_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_expire_days: int = Field(default=30, ge=1, le=90)
    jwt_issuer: str = Field(min_length=1)
    jwt_audience: str = Field(min_length=1)

    cors_origins: list[str] = []
    # Host names this API answers to (JSON list). Required in production; when empty outside
    # production, Host is not checked (e.g. a phone reaching a dev machine by LAN IP).
    allowed_hosts: list[str] = []

    # Google sign-in (Step 8). All three or none: unset means the endpoints answer 404.
    google_client_id: str | None = None
    google_client_secret: SecretStr | None = None
    # Where Google sends the browser back: an https page/universal link that hands `code` and
    # `state` to the client. Must exactly match the URI registered in the Google console.
    google_redirect_uri: str | None = None

    # Sign in with Apple (Step 9). All five or none: unset means the endpoints answer 404.
    apple_team_id: str | None = None
    apple_key_id: str | None = None
    # The Services ID (e.g. com.example.app.signin): the `aud` of Apple's ID tokens.
    apple_client_id: str | None = None
    # The .p8 key's PEM text (newlines may be escaped as \n). Only ever from a secret manager.
    apple_private_key: SecretStr | None = None
    apple_redirect_uri: str | None = None

    @property
    def docs_enabled(self) -> bool:
        return self.environment is not Environment.PRODUCTION

    @property
    def google_oauth_enabled(self) -> bool:
        return self.google_client_id is not None

    @property
    def apple_oauth_enabled(self) -> bool:
        return self.apple_client_id is not None

    @property
    def https_required(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @field_validator("jwt_secret")
    @classmethod
    def _validate_jwt_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if len(secret) < MIN_JWT_SECRET_LENGTH:
            raise ValueError(f"jwt_secret must be at least {MIN_JWT_SECRET_LENGTH} characters")
        lowered = secret.lower()
        if (
            any(marker in lowered for marker in PLACEHOLDER_MARKERS)
            or len(set(secret)) < MIN_JWT_SECRET_DISTINCT_CHARS
        ):
            raise ValueError("jwt_secret looks like a placeholder or low-entropy value")
        return value

    @field_validator("database_url", "migration_database_url")
    @classmethod
    def _validate_database_url(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith(REQUIRED_DB_SCHEME):
            raise ValueError(f"database URL must use the {REQUIRED_DB_SCHEME} scheme")
        return value

    @field_validator("cors_origins")
    @classmethod
    def _reject_wildcard_cors(cls, value: list[str]) -> list[str]:
        if "*" in value:
            raise ValueError("wildcard CORS origin is not allowed")
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def _validate_allowed_hosts(cls, value: list[str]) -> list[str]:
        # Messages never quote the entry: it may name internal infrastructure.
        if "*" in value:
            raise ValueError("wildcard ALLOWED_HOSTS entry '*' is not allowed")
        if not all(_ALLOWED_HOST.fullmatch(host) for host in value):
            raise ValueError(
                "ALLOWED_HOSTS entries must be bare lowercase hostnames (no scheme, port or path)"
            )
        return value

    @model_validator(mode="after")
    def _validate_google_oauth(self) -> Self:
        values = (self.google_client_id, self.google_client_secret, self.google_redirect_uri)
        if all(value is None for value in values):
            return self
        if any(value is None or value == "" for value in values) or not (
            self.google_client_secret and self.google_client_secret.get_secret_value()
        ):
            raise ValueError(
                "GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI"
                " must be set together"
            )
        uri = urlsplit(self.google_redirect_uri or "")
        local_http = (
            uri.scheme == "http"
            and uri.hostname in ("localhost", "127.0.0.1")
            and self.environment is not Environment.PRODUCTION
        )
        if (uri.scheme != "https" and not local_http) or not uri.hostname or uri.fragment:
            raise ValueError(
                "GOOGLE_REDIRECT_URI must be an absolute https URL without a fragment"
                " (http://localhost is allowed outside production)"
            )
        return self

    @model_validator(mode="after")
    def _validate_apple_oauth(self) -> Self:
        values = (
            self.apple_team_id,
            self.apple_key_id,
            self.apple_client_id,
            self.apple_private_key,
            self.apple_redirect_uri,
        )
        if all(value is None for value in values):
            return self
        if any(value is None for value in values):
            raise ValueError(
                "APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_CLIENT_ID, APPLE_PRIVATE_KEY and"
                " APPLE_REDIRECT_URI must be set together"
            )
        if not _APPLE_ID.fullmatch(self.apple_team_id or ""):
            raise ValueError("APPLE_TEAM_ID must be 10 uppercase letters or digits")
        if not _APPLE_ID.fullmatch(self.apple_key_id or ""):
            raise ValueError("APPLE_KEY_ID must be 10 uppercase letters or digits")
        if not _APPLE_CLIENT_ID.fullmatch(self.apple_client_id or ""):
            raise ValueError("APPLE_CLIENT_ID must be a Services ID like com.example.app.signin")
        try:
            load_apple_private_key(_secret(self.apple_private_key))
        except ValueError:
            raise ValueError(
                "APPLE_PRIVATE_KEY must be the PEM text of an ES256 (P-256) .p8 key"
            ) from None
        uri = urlsplit(self.apple_redirect_uri or "")
        # Apple only accepts https redirect URIs (no http, no localhost exceptions).
        if uri.scheme != "https" or not uri.hostname or uri.fragment:
            raise ValueError("APPLE_REDIRECT_URI must be an absolute https URL without a fragment")
        return self

    @model_validator(mode="after")
    def _enforce_production_hardening(self) -> Self:
        if self.environment is not Environment.PRODUCTION:
            return self
        if self.debug:
            raise ValueError("debug must be disabled in production")
        insecure = [origin for origin in self.cors_origins if not origin.startswith("https://")]
        if insecure:
            raise ValueError("production CORS origins must use https")
        if not self.allowed_hosts:
            raise ValueError("ALLOWED_HOSTS must be set in production")
        if any("*" in host for host in self.allowed_hosts):
            raise ValueError("wildcard ALLOWED_HOSTS patterns are not allowed in production")
        return self


def _secret(value: SecretStr | None) -> str:
    return value.get_secret_value() if value is not None else ""


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment / .env
