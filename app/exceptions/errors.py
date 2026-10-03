"""Application errors: fixed, safe messages. Internal causes are never attached or exposed."""


class AppError(Exception):
    status_code: int = 400
    code: str = "bad_request"
    message: str = "Bad request"

    def __init__(self) -> None:
        super().__init__(self.message)


class InvalidRefreshTokenError(AppError):
    """Unknown, malformed, expired, revoked and reused tokens are deliberately indistinguishable."""

    status_code = 401
    code = "invalid_refresh_token"
    message = "Invalid refresh token"
