"""Domain errors. Each maps to an HTTP status and a stable machine-readable code."""

from __future__ import annotations


class AppError(Exception):
    status_code: int = 400
    code: str = "bad_request"

    def __init__(self, message: str, *, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.headers = headers


class NotAuthenticated(AppError):
    status_code = 401
    code = "not_authenticated"

    def __init__(self, message: str = "Not authenticated") -> None:
        super().__init__(message, headers={"WWW-Authenticate": "Bearer"})


class InvalidCredentials(NotAuthenticated):
    code = "invalid_credentials"

    def __init__(self) -> None:
        super().__init__("Invalid email or password")


class InvalidToken(NotAuthenticated):
    code = "invalid_token"

    def __init__(self, message: str = "Invalid or expired token") -> None:
        super().__init__(message)


class TokenReuseDetected(InvalidToken):
    code = "refresh_token_reused"

    def __init__(self) -> None:
        super().__init__("Refresh token reuse detected; all sessions in this family were revoked")


class PermissionDenied(AppError):
    status_code = 403
    code = "permission_denied"

    def __init__(self, message: str = "You do not have permission to do this") -> None:
        super().__init__(message)


class CsrfFailed(PermissionDenied):
    code = "csrf_failed"

    def __init__(self) -> None:
        super().__init__("Missing or invalid X-CSRF-Token header")


class EmailNotVerified(PermissionDenied):
    code = "email_not_verified"

    def __init__(self) -> None:
        super().__init__("Verify your email address before uploading or sharing files")


class InvalidVerificationToken(AppError):
    status_code = 400
    code = "invalid_verification_token"

    def __init__(self) -> None:
        super().__init__("Invalid or expired verification link")


class InvalidResetToken(AppError):
    status_code = 400
    code = "invalid_reset_token"

    def __init__(self) -> None:
        super().__init__("Invalid or expired password reset link")


class NotFound(AppError):
    status_code = 404
    code = "not_found"


class Conflict(AppError):
    status_code = 409
    code = "conflict"


class Gone(AppError):
    status_code = 410
    code = "gone"


class PayloadTooLarge(AppError):
    status_code = 413
    code = "payload_too_large"


class ValidationFailed(AppError):
    status_code = 422
    code = "validation_failed"


class RateLimited(AppError):
    status_code = 429
    code = "rate_limited"

    def __init__(self, retry_after_seconds: int) -> None:
        retry = max(1, retry_after_seconds)
        super().__init__("Too many requests", headers={"Retry-After": str(retry)})
        self.retry_after_seconds = retry


class ServiceUnavailable(AppError):
    status_code = 503
    code = "service_unavailable"


class OAuthError(AppError):
    status_code = 400
    code = "oauth_error"
