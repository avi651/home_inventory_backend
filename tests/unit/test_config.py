from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import Environment, Settings

STRONG_SECRET = "kJ8s2nQw9vL4xR7tY1uZ3pA6dF0gH5jK-mN8bV2cX4zQ"
DB_PASSWORD = "db-pass-Xy7Qw3"


def valid_settings(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "environment": "local",
        "database_url": f"postgresql+psycopg://app:{DB_PASSWORD}@localhost:5432/home_inventory",
        "migration_database_url": (
            f"postgresql+psycopg://migrator:{DB_PASSWORD}@localhost:5432/home_inventory"
        ),
        "jwt_secret": STRONG_SECRET,
        "jwt_algorithm": "HS256",
        "access_token_expire_minutes": 15,
        "refresh_token_expire_days": 30,
        "jwt_issuer": "home-inventory-api",
        "jwt_audience": "home-inventory-mobile",
        "cors_origins": [],
    }
    values.update(overrides)
    return values


def build(**overrides: Any) -> Settings:
    return Settings(_env_file=None, **valid_settings(**overrides))


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure real environment variables never leak into these tests."""
    for name in valid_settings():
        monkeypatch.delenv(name.upper(), raising=False)
    monkeypatch.delenv("DEBUG", raising=False)


class TestValidConfiguration:
    def test_loads_valid_values(self) -> None:
        settings = build()

        assert settings.environment is Environment.LOCAL
        assert settings.jwt_secret.get_secret_value() == STRONG_SECRET
        assert settings.access_token_expire_minutes == 15
        assert settings.refresh_token_expire_days == 30
        assert settings.debug is False

    def test_reads_from_environment_variables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name, value in valid_settings(access_token_expire_minutes="10").items():
            monkeypatch.setenv(name.upper(), str(value) if value != [] else "[]")

        settings = Settings(_env_file=None)

        assert settings.access_token_expire_minutes == 10

    def test_docs_enabled_outside_production(self) -> None:
        assert build(environment="local").docs_enabled is True

    def test_docs_disabled_in_production(self) -> None:
        assert build(environment="production").docs_enabled is False


class TestJwtSecret:
    def test_missing_secret_is_rejected(self) -> None:
        values = valid_settings()
        del values["jwt_secret"]

        with pytest.raises(ValidationError, match="jwt_secret"):
            Settings(_env_file=None, **values)

    def test_short_secret_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 32"):
            build(jwt_secret="too-short-secret")

    @pytest.mark.parametrize(
        "weak",
        [
            "changeme-changeme-changeme-changeme",
            "<generate-a-random-secret>-padding-padding",
            "a" * 64,
            "secretsecretsecretsecretsecretsecret",
        ],
    )
    def test_placeholder_or_low_entropy_secret_is_rejected(self, weak: str) -> None:
        with pytest.raises(ValidationError, match="placeholder or low-entropy"):
            build(jwt_secret=weak)


class TestJwtAlgorithm:
    @pytest.mark.parametrize("algorithm", ["none", "None", "RS256", "HS1", ""])
    def test_only_allow_listed_algorithms(self, algorithm: str) -> None:
        with pytest.raises(ValidationError, match="jwt_algorithm"):
            build(jwt_algorithm=algorithm)


class TestTokenLifetimes:
    @pytest.mark.parametrize("minutes", [0, -1, 61])
    def test_access_token_lifetime_must_be_short(self, minutes: int) -> None:
        with pytest.raises(ValidationError, match="access_token_expire_minutes"):
            build(access_token_expire_minutes=minutes)

    @pytest.mark.parametrize("days", [0, 91])
    def test_refresh_token_lifetime_is_bounded(self, days: int) -> None:
        with pytest.raises(ValidationError, match="refresh_token_expire_days"):
            build(refresh_token_expire_days=days)

    @pytest.mark.parametrize("field", ["jwt_issuer", "jwt_audience"])
    def test_issuer_and_audience_are_required(self, field: str) -> None:
        with pytest.raises(ValidationError, match=field):
            build(**{field: ""})


class TestDatabaseUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "sqlite:///./test.db",
            "sqlite+aiosqlite:///./test.db",
            "mysql://u:p@localhost/db",
            "postgresql://u:p@localhost/db",  # psycopg2 default driver: not installed
        ],
    )
    @pytest.mark.parametrize("field", ["database_url", "migration_database_url"])
    def test_only_postgresql_psycopg_is_accepted(self, field: str, url: str) -> None:
        with pytest.raises(ValidationError, match="postgresql\\+psycopg"):
            build(**{field: url})


class TestSecretsAreNotExposed:
    def test_repr_masks_secrets(self) -> None:
        text = repr(build())

        assert STRONG_SECRET not in text
        assert DB_PASSWORD not in text

    def test_model_dump_masks_secrets(self) -> None:
        dumped = str(build().model_dump())

        assert STRONG_SECRET not in dumped
        assert DB_PASSWORD not in dumped

    def test_validation_error_does_not_echo_secret(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            build(jwt_secret="short-but-sensitive")

        assert "short-but-sensitive" not in str(exc_info.value)


class TestProductionHardening:
    def test_production_rejects_debug(self) -> None:
        with pytest.raises(ValidationError, match="debug"):
            build(environment="production", debug=True)

    def test_production_rejects_wildcard_cors(self) -> None:
        with pytest.raises(ValidationError, match="CORS"):
            build(environment="production", cors_origins=["*"])

    def test_production_rejects_non_https_cors(self) -> None:
        with pytest.raises(ValidationError, match="https"):
            build(environment="production", cors_origins=["http://example.com"])

    def test_production_accepts_https_origins(self) -> None:
        settings = build(environment="production", cors_origins=["https://app.example.com"])

        assert settings.cors_origins == ["https://app.example.com"]

    def test_wildcard_cors_rejected_everywhere(self) -> None:
        # The API uses bearer credentials; "*" is never a safe default.
        with pytest.raises(ValidationError, match="CORS"):
            build(environment="local", cors_origins=["*"])
