from enum import StrEnum
from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_JWT_SECRET_LENGTH = 32
MIN_JWT_SECRET_DISTINCT_CHARS = 10
PLACEHOLDER_MARKERS = ("changeme", "change-me", "placeholder", "example", "generate", "<", ">")
REQUIRED_DB_SCHEME = "postgresql+psycopg://"


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

    @property
    def docs_enabled(self) -> bool:
        return self.environment is not Environment.PRODUCTION

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

    @model_validator(mode="after")
    def _enforce_production_hardening(self) -> Self:
        if self.environment is not Environment.PRODUCTION:
            return self
        if self.debug:
            raise ValueError("debug must be disabled in production")
        insecure = [origin for origin in self.cors_origins if not origin.startswith("https://")]
        if insecure:
            raise ValueError("production CORS origins must use https")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment / .env
