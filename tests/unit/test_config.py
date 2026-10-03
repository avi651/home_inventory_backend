from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
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
    for name in [
        *valid_settings(),
        "allowed_hosts",
        "google_client_id",
        "google_client_secret",
        "google_redirect_uri",
        "apple_team_id",
        "apple_key_id",
        "apple_client_id",
        "apple_private_key",
        "apple_redirect_uri",
    ]:
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
        settings = build(environment="production", allowed_hosts=["api.example.com"])

        assert settings.docs_enabled is False


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
        settings = build(
            environment="production",
            allowed_hosts=["api.example.com"],
            cors_origins=["https://app.example.com"],
        )

        assert settings.cors_origins == ["https://app.example.com"]

    def test_wildcard_cors_rejected_everywhere(self) -> None:
        # The API uses bearer credentials; "*" is never a safe default.
        with pytest.raises(ValidationError, match="CORS"):
            build(environment="local", cors_origins=["*"])


class TestAllowedHosts:
    def test_defaults_to_no_host_restriction_outside_production(self) -> None:
        assert build().allowed_hosts == []

    def test_local_may_configure_explicit_hosts(self) -> None:
        settings = build(allowed_hosts=["localhost", "127.0.0.1"])

        assert settings.allowed_hosts == ["localhost", "127.0.0.1"]

    def test_production_requires_allowed_hosts(self) -> None:
        with pytest.raises(ValidationError, match="ALLOWED_HOSTS"):
            build(environment="production")

    @pytest.mark.parametrize("hosts", [["*"], ["api.example.com", "*"], ["*.example.com"]])
    def test_production_rejects_wildcards(self, hosts: list[str]) -> None:
        with pytest.raises(ValidationError, match="wildcard"):
            build(environment="production", allowed_hosts=hosts)

    def test_bare_wildcard_rejected_everywhere(self) -> None:
        # "*" would silently disable host validation.
        with pytest.raises(ValidationError, match="wildcard"):
            build(environment="local", allowed_hosts=["*"])

    @pytest.mark.parametrize(
        "host",
        [
            "https://api.example.com",
            "api.example.com:443",
            "api.example.com/",
            "API.example.com",
            " api.example.com",
            "",
        ],
    )
    def test_entries_must_be_bare_lowercase_hostnames(self, host: str) -> None:
        with pytest.raises(ValidationError, match="hostname"):
            build(environment="production", allowed_hosts=[host])

    def test_production_accepts_explicit_hosts(self) -> None:
        settings = build(environment="production", allowed_hosts=["api.example.com"])

        assert settings.allowed_hosts == ["api.example.com"]

    def test_https_required_only_in_production(self) -> None:
        assert build().https_required is False
        assert build(environment="test").https_required is False
        assert build(environment="production", allowed_hosts=["api.example.com"]).https_required

    def test_reads_json_list_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ALLOWED_HOSTS", '["api.example.com"]')
        values = valid_settings(environment="production")

        settings = Settings(_env_file=None, **values)

        assert settings.allowed_hosts == ["api.example.com"]

    def test_validation_error_does_not_echo_configuration(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            build(environment="production", allowed_hosts=["https://internal-lb.corp:8443"])

        assert "internal-lb.corp" not in str(exc_info.value)


GOOGLE = {
    "google_client_id": "1234-abc.apps.googleusercontent.com",
    "google_client_secret": "GOCSPX-test-secret-value-Zr8",
    "google_redirect_uri": "https://app.example.com/oauth/google/callback",
}


class TestGoogleOAuthSettings:
    def test_disabled_by_default(self) -> None:
        assert build().google_oauth_enabled is False

    def test_enabled_when_fully_configured(self) -> None:
        assert build(**GOOGLE).google_oauth_enabled is True

    @pytest.mark.parametrize("missing", list(GOOGLE))
    def test_partial_configuration_fails_fast(self, missing: str) -> None:
        values = {k: v for k, v in GOOGLE.items() if k != missing}

        with pytest.raises(ValidationError, match="GOOGLE_"):
            build(**values)

    @pytest.mark.parametrize(
        "uri",
        [
            "app.example.com/callback",
            "ftp://app.example.com/cb",
            "https://app.example.com/cb#fragment",
            "https:///no-host",
            "com.example.app:/oauth2redirect",
        ],
    )
    def test_redirect_uri_must_be_an_absolute_http_url(self, uri: str) -> None:
        with pytest.raises(ValidationError, match="GOOGLE_REDIRECT_URI"):
            build(**{**GOOGLE, "google_redirect_uri": uri})

    def test_local_may_use_http_localhost(self) -> None:
        settings = build(**{**GOOGLE, "google_redirect_uri": "http://localhost:3000/cb"})

        assert settings.google_oauth_enabled

    @pytest.mark.parametrize("uri", ["http://localhost:3000/cb", "http://app.example.com/cb"])
    def test_production_requires_https_redirect(self, uri: str) -> None:
        with pytest.raises(ValidationError, match="GOOGLE_REDIRECT_URI"):
            build(
                environment="production",
                allowed_hosts=["api.example.com"],
                **{**GOOGLE, "google_redirect_uri": uri},
            )

    def test_client_secret_is_masked(self) -> None:
        settings = build(**GOOGLE)

        assert GOOGLE["google_client_secret"] not in repr(settings)
        assert GOOGLE["google_client_secret"] not in str(settings.model_dump())


def apple_key_pem(curve: Any = None) -> str:
    key = ec.generate_private_key(curve or ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


APPLE_KEY = apple_key_pem()
APPLE = {
    "apple_team_id": "ABCDE12345",
    "apple_key_id": "KEY0123456",
    "apple_client_id": "com.example.homeinventory.signin",
    "apple_private_key": APPLE_KEY,
    "apple_redirect_uri": "https://app.example.com/oauth/apple/callback",
}


class TestAppleOAuthSettings:
    def test_disabled_by_default(self) -> None:
        assert build().apple_oauth_enabled is False

    def test_enabled_when_fully_configured(self) -> None:
        assert build(**APPLE).apple_oauth_enabled is True

    @pytest.mark.parametrize("missing", list(APPLE))
    def test_partial_configuration_fails_fast(self, missing: str) -> None:
        values = {k: v for k, v in APPLE.items() if k != missing}

        with pytest.raises(ValidationError, match="APPLE_"):
            build(**values)

    @pytest.mark.parametrize("field", ["apple_team_id", "apple_key_id"])
    @pytest.mark.parametrize("value", ["abcde12345", "ABCDE1234", "ABCDE123456", "ABCDE-1234"])
    def test_team_and_key_ids_are_ten_uppercase_alphanumerics(self, field: str, value: str) -> None:
        with pytest.raises(ValidationError, match="APPLE_"):
            build(**{**APPLE, field: value})

    @pytest.mark.parametrize("client_id", ["", "has space", "x" * 256])
    def test_client_id_must_be_a_services_identifier(self, client_id: str) -> None:
        with pytest.raises(ValidationError, match="APPLE_CLIENT_ID"):
            build(**{**APPLE, "apple_client_id": client_id})

    def test_private_key_may_use_escaped_newlines(self) -> None:
        escaped = APPLE_KEY.replace("\n", "\\n")

        assert build(**{**APPLE, "apple_private_key": escaped}).apple_oauth_enabled

    @pytest.mark.parametrize(
        "key_factory",
        [
            pytest.param(lambda: "not a key", id="garbage"),
            pytest.param(
                lambda: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
                id="truncated",
            ),
            pytest.param(lambda: apple_key_pem(ec.SECP384R1()), id="p384"),
            pytest.param(lambda: _rsa_pem(), id="rsa"),
        ],
    )
    def test_private_key_must_be_an_es256_p256_key(self, key_factory: Any) -> None:
        key = key_factory()

        with pytest.raises(ValidationError, match="APPLE_PRIVATE_KEY") as exc_info:
            build(**{**APPLE, "apple_private_key": key})

        assert key not in str(exc_info.value)
        assert "MII" not in str(exc_info.value)

    @pytest.mark.parametrize(
        "uri",
        [
            "http://app.example.com/cb",
            "http://localhost:3000/cb",  # Apple does not accept localhost or http redirects
            "https://app.example.com/cb#fragment",
            "app.example.com/cb",
            "com.example.app:/callback",
        ],
    )
    def test_redirect_uri_must_be_https(self, uri: str) -> None:
        with pytest.raises(ValidationError, match="APPLE_REDIRECT_URI"):
            build(**{**APPLE, "apple_redirect_uri": uri})

    def test_production_accepts_a_full_configuration(self) -> None:
        settings = build(environment="production", allowed_hosts=["api.example.com"], **APPLE)

        assert settings.apple_oauth_enabled

    def test_private_key_is_masked(self) -> None:
        settings = build(**APPLE)
        body = "".join(APPLE_KEY.splitlines()[1:-1])

        for text in (repr(settings), str(settings.model_dump())):
            assert body[:40] not in text
            assert "PRIVATE KEY" not in text


def _rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
