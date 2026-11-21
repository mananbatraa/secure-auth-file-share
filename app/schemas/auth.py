from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.core.rbac import Role


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=16, max_length=512)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class TokenPair(BaseModel):
    access_token: str
    # None when the refresh token was delivered as an HttpOnly cookie instead.
    refresh_token: str | None
    token_type: Literal["bearer"] = "bearer"  # noqa: S105
    expires_in: int
    refresh_expires_in: int
    # Cookie delivery only: echo this in X-CSRF-Token on /auth/refresh and /auth/logout.
    csrf_token: str | None = None


class MfaChallenge(BaseModel):
    """Returned by login instead of tokens when the account has two-factor auth on."""

    mfa_required: Literal[True] = True
    mfa_token: str
    expires_in: int
    methods: list[Literal["totp", "recovery_code"]] = ["totp", "recovery_code"]


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    role: Role
    is_active: bool
    email_verified: bool
    mfa_enabled: bool
    created_at: datetime


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=16, max_length=2048)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=16, max_length=2048)
    new_password: str = Field(min_length=1, max_length=256)


class UserAdminUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


_TOTP_PATTERN = r"^[0-9]{6}$"


class MfaStatus(BaseModel):
    enabled: bool
    # Enrolment started (seed generated) but not confirmed with a code yet.
    pending: bool
    recovery_codes_remaining: int


class TotpSetupRequest(BaseModel):
    # Required when the account has a password; OAuth-only accounts omit it.
    password: str | None = Field(default=None, min_length=1, max_length=256)


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class TotpCodeRequest(BaseModel):
    code: str = Field(pattern=_TOTP_PATTERN)


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


class MfaDisableRequest(BaseModel):
    password: str | None = Field(default=None, min_length=1, max_length=256)
    code: str | None = Field(default=None, pattern=_TOTP_PATTERN)
    recovery_code: str | None = Field(default=None, min_length=8, max_length=32)


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(min_length=16, max_length=2048)
    code: str | None = Field(default=None, pattern=_TOTP_PATTERN)
    recovery_code: str | None = Field(default=None, min_length=8, max_length=32)
