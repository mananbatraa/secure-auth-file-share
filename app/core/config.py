"""Application settings, loaded from environment variables (and an optional .env file)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_JWT_SECRET = "dev-only-insecure-secret-change-me-0123456789"  # noqa: S105


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "secure-auth-file-share"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    cors_origins: list[str] = Field(default_factory=list)
    # Only honour X-Forwarded-For when the app sits behind a proxy you control.
    trust_proxy_headers: bool = False

    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/fileshare"
    db_pool_size: int = 10
    redis_url: str = "redis://localhost:6379/0"

    # --- tokens -------------------------------------------------------------------------
    jwt_secret: SecretStr = SecretStr(_DEV_JWT_SECRET)
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    jwt_issuer: str = "secure-auth-file-share"
    jwt_audience: str = "secure-auth-file-share-api"
    access_token_ttl_seconds: int = Field(default=900, ge=30)
    refresh_token_ttl_seconds: int = Field(default=14 * 24 * 3600, ge=300)

    # --- login throttling ---------------------------------------------------------------
    login_max_attempts_per_email: int = Field(default=5, ge=1)
    login_max_attempts_per_ip: int = Field(default=20, ge=1)
    login_window_seconds: int = Field(default=300, ge=1)
    share_link_max_hits_per_ip: int = Field(default=60, ge=1)
    share_link_window_seconds: int = Field(default=60, ge=1)
    # When Redis is unreachable: fail closed (reject logins) unless explicitly opted out.
    rate_limit_fail_open: bool = False

    password_min_length: int = Field(default=12, ge=8)

    # --- email verification -------------------------------------------------------------
    # Unverified accounts can sign in and read what is shared with them, but cannot
    # upload or share until they prove they own the address.
    require_verified_email: bool = True
    email_verification_ttl_seconds: int = Field(default=24 * 3600, ge=300)
    # Where the link in the email points (your frontend, which POSTs the token to
    # /auth/verify-email). Must contain "{token}".
    email_verification_url: str = "http://localhost:3000/verify-email?token={token}"
    email_verification_resend_limit: int = Field(default=3, ge=1)
    email_verification_resend_window_seconds: int = Field(default=3600, ge=1)
    # --- password reset -----------------------------------------------------------------
    password_reset_ttl_seconds: int = Field(default=1800, ge=60, le=24 * 3600)
    # Your frontend page, which POSTs the token and a new password to
    # /auth/password-reset/confirm. Must contain "{token}".
    password_reset_url: str = "http://localhost:3000/reset-password?token={token}"  # noqa: S105
    password_reset_max_per_email: int = Field(default=3, ge=1)
    password_reset_max_per_ip: int = Field(default=10, ge=1)
    password_reset_window_seconds: int = Field(default=3600, ge=1)

    # Without SMTP_HOST the email is only logged (development).
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = True
    smtp_timeout_seconds: float = 10.0
    mail_from: str = "Secure File Share <no-reply@localhost>"

    # --- object storage (S3 / MinIO) ----------------------------------------------------
    s3_endpoint_url: str | None = None
    # Endpoint used when signing URLs handed to browsers (e.g. http://localhost:9000 when
    # the API talks to MinIO over the docker network as http://minio:9000).
    s3_public_endpoint_url: str | None = None
    s3_region: str = "us-east-1"
    s3_bucket: str = "fileshare"
    s3_access_key_id: str | None = None
    s3_secret_access_key: SecretStr | None = None
    s3_create_bucket: bool = False
    max_upload_bytes: int = Field(default=50 * 1024 * 1024, ge=1)
    # Direct-to-S3 uploads bypass the API, so they can be much larger.
    direct_upload_max_bytes: int = Field(default=5 * 1024 * 1024 * 1024, ge=1)
    upload_intent_ttl_seconds: int = Field(default=900, ge=60)
    download_url_default_ttl_seconds: int = Field(default=300, ge=10)
    download_url_max_ttl_seconds: int = Field(default=3600, ge=10)
    share_link_redirect_ttl_seconds: int = Field(default=60, ge=10)
    share_link_max_ttl_seconds: int = Field(default=7 * 24 * 3600, ge=60)

    # --- background cleanup (python -m app.cleanup) -----------------------------------
    cleanup_interval_seconds: int = Field(default=3600, ge=10)
    cleanup_batch_size: int = Field(default=500, ge=1, le=10_000)
    # Expired upload intents are discarded this long after expiry. Must exceed the
    # window in which an expired intent can still be completed (5 minutes).
    cleanup_upload_grace_seconds: int = Field(default=3600, ge=600)
    # Expired refresh tokens and dead share links are kept this long (reuse detection,
    # forensics, owners' link listings) before they are deleted.
    cleanup_retention_seconds: int = Field(default=7 * 24 * 3600, ge=0)

    # --- OAuth --------------------------------------------------------------------------
    oauth_redirect_base_url: str = "http://localhost:8000"
    oauth_state_ttl_seconds: int = 600
    github_client_id: str | None = None
    github_client_secret: SecretStr | None = None
    google_client_id: str | None = None
    google_client_secret: SecretStr | None = None

    @model_validator(mode="after")
    def _check_production_safety(self) -> Settings:
        secret = self.jwt_secret.get_secret_value()
        if self.environment == "production":
            if secret == _DEV_JWT_SECRET:
                raise ValueError("JWT_SECRET must be set in production")
            if len(secret) < 32:
                raise ValueError("JWT_SECRET must be at least 32 characters")
        if "{token}" not in self.email_verification_url:
            raise ValueError("EMAIL_VERIFICATION_URL must contain {token}")
        if "{token}" not in self.password_reset_url:
            raise ValueError("PASSWORD_RESET_URL must contain {token}")
        if self.download_url_default_ttl_seconds > self.download_url_max_ttl_seconds:
            raise ValueError("DOWNLOAD_URL_DEFAULT_TTL_SECONDS exceeds the max TTL")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
