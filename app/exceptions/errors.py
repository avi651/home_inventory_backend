"""Application errors: fixed, safe messages. Internal causes are never attached or exposed."""

from collections.abc import Sequence
from typing import Any


class AppError(Exception):
    status_code: int = 400
    code: str = "bad_request"
    message: str = "Bad request"

    def __init__(
        self, *, headers: dict[str, str] | None = None, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(self.message)
        self.headers = headers
        self.details = details or {}


class AuthenticationRequiredError(AppError):
    """Missing, malformed, invalid or expired access token, or a revoked/inactive principal."""

    status_code = 401
    code = "unauthorized"
    message = "Authentication required"

    def __init__(self) -> None:
        super().__init__(headers={"WWW-Authenticate": "Bearer"})


class InvalidCredentialsError(AppError):
    """Unknown email, wrong password, inactive user and non-password accounts look identical."""

    status_code = 401
    code = "invalid_credentials"
    message = "Invalid email or password"


class InvalidRefreshTokenError(AppError):
    """Unknown, malformed, expired, revoked and reused tokens are deliberately indistinguishable."""

    status_code = 401
    code = "invalid_refresh_token"
    message = "Invalid refresh token"


class RegistrationUnavailableError(AppError):
    """Generic on purpose (ARCHITECTURE.md D2): never confirms that an email is registered."""

    status_code = 409
    code = "registration_unavailable"
    message = "Unable to register with these details"


class WeakPasswordError(AppError):
    status_code = 422
    code = "weak_password"
    message = "Password does not meet the requirements"

    def __init__(self, violations: Sequence[str]) -> None:
        self.violations = list(violations)
        super().__init__(details={"violations": [str(v) for v in self.violations]})


class RateLimitedError(AppError):
    status_code = 429
    code = "too_many_requests"
    message = "Too many requests"

    def __init__(self, retry_after: int) -> None:
        super().__init__(headers={"Retry-After": str(retry_after)})


class OAuthSignInFailedError(AppError):
    """Unknown/expired/replayed state, rejected code or ID token, or an inactive account."""

    status_code = 401
    code = "oauth_failed"
    message = "Unable to sign in with this provider"


class AccountLinkRequiredError(AppError):
    """A new provider identity's verified email already belongs to an account (D1: never merge).

    Only the verified owner of that email address can reach this, so it is not an
    enumeration oracle for third parties.
    """

    status_code = 409
    code = "account_link_required"
    message = "Sign in with your existing account to link this sign-in method"


class ProviderUnavailableError(AppError):
    """The identity provider timed out, failed or answered malformed responses."""

    status_code = 503
    code = "provider_unavailable"
    message = "Sign-in provider is unavailable"


class ProviderNotConfiguredError(AppError):
    """The provider is not configured on this deployment: its endpoints behave as absent."""

    status_code = 404
    code = "not_found"
    message = "Not found"


class HomeNotFoundError(AppError):
    """Nonexistent and not-yours are deliberately identical (and identical to a routing 404)."""

    status_code = 404
    code = "not_found"
    message = "Not found"


class HomeNameTakenError(AppError):
    status_code = 409
    code = "home_name_taken"
    message = "A home with this name already exists"


class HomeLimitReachedError(AppError):
    status_code = 409
    code = "home_limit_reached"
    message = "Home limit reached"
