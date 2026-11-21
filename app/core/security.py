"""Password hashing, JWT access tokens and opaque-token helpers."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pwdlib import PasswordHash

from app.core.config import Settings
from app.core.errors import (
    InvalidMfaToken,
    InvalidResetToken,
    InvalidToken,
    InvalidVerificationToken,
)

_password_hash = PasswordHash.recommended()  # Argon2id
# Verified against when the user does not exist, so login timing doesn't leak which
# emails are registered.
_DUMMY_HASH = _password_hash.hash(secrets.token_urlsafe(16))


def utcnow() -> datetime:
    return datetime.now(UTC)


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, hashed: str | None) -> bool:
    if hashed is None:
        _password_hash.verify(password, _DUMMY_HASH)
        return False
    return _password_hash.verify(password, hashed)


def burn_password_check(password: str) -> None:
    """Spend the same time as a real verification (user not found)."""
    _password_hash.verify(password, _DUMMY_HASH)


def new_opaque_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_opaque_token(token: str) -> str:
    """Opaque tokens are high-entropy, so a fast hash is enough; we never store them raw."""
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token_for(settings: Settings, refresh_token: str) -> str:
    """The CSRF token paired with a cookie-held refresh token (signed double submit).

    Derived from the refresh token with the server key, so it rotates with it, cannot
    be forged by someone who can only plant cookies, and needs no storage.
    """
    key = settings.jwt_secret.get_secret_value().encode()
    return hmac.new(key, b"csrf:" + refresh_token.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class AccessClaims:
    user_id: uuid.UUID
    role: str
    token_version: int
    jti: str
    expires_at: datetime


def create_access_token(
    settings: Settings, *, user_id: uuid.UUID, role: str, token_version: int
) -> tuple[str, datetime]:
    now = utcnow()
    expires_at = now + timedelta(seconds=settings.access_token_ttl_seconds)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "role": role,
        "ver": token_version,
        "type": "access",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(
        payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm
    )
    return token, expires_at


def _verification_audience(settings: Settings) -> str:
    # A different audience, so a verification token can never pass as an access token.
    return f"{settings.jwt_audience}:email-verification"


def email_fingerprint(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()


def create_email_verification_token(settings: Settings, *, user_id: uuid.UUID, email: str) -> str:
    """A signed, expiring token bound to the user *and* the address it was sent to."""
    now = utcnow()
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "eml": email_fingerprint(email),
        "type": "email_verification",
        "iss": settings.jwt_issuer,
        "aud": _verification_audience(settings),
        "iat": now,
        "exp": now + timedelta(seconds=settings.email_verification_ttl_seconds),
    }
    return jwt.encode(
        payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm
    )


def decode_email_verification_token(settings: Settings, token: str) -> tuple[uuid.UUID, str]:
    """Return ``(user_id, email_fingerprint)``; raises :class:`InvalidVerificationToken`."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            audience=_verification_audience(settings),
            issuer=settings.jwt_issuer,
            options={"require": ["sub", "exp", "iat", "type", "eml"]},
        )
        if payload.get("type") != "email_verification":
            raise InvalidVerificationToken()
        return uuid.UUID(payload["sub"]), str(payload["eml"])
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise InvalidVerificationToken() from exc


def _password_reset_audience(settings: Settings) -> str:
    return f"{settings.jwt_audience}:password-reset"


def password_fingerprint(settings: Settings, hashed_password: str | None) -> str:
    """A keyed digest of the *current* password hash (empty for password-less accounts).

    A reset token carries it, so the token dies as soon as the password changes: the
    reset itself, a change-password, or an OAuth link that removes the password. That
    makes the token single-use without a table. It is an HMAC, not a plain hash, so the
    (readable) token reveals nothing about the stored hash.
    """
    key = settings.jwt_secret.get_secret_value().encode()
    msg = (hashed_password or "").encode()
    return hmac.new(key, b"password-reset:" + msg, hashlib.sha256).hexdigest()


def create_password_reset_token(
    settings: Settings, *, user_id: uuid.UUID, email: str, hashed_password: str | None
) -> str:
    """A short-lived token bound to the user, their address and their current password."""
    now = utcnow()
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "eml": email_fingerprint(email),
        "pwd": password_fingerprint(settings, hashed_password),
        "type": "password_reset",
        "iss": settings.jwt_issuer,
        "aud": _password_reset_audience(settings),
        "iat": now,
        "exp": now + timedelta(seconds=settings.password_reset_ttl_seconds),
    }
    return jwt.encode(
        payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm
    )


@dataclass(frozen=True, slots=True)
class PasswordResetClaims:
    user_id: uuid.UUID
    email_fingerprint: str
    password_fingerprint: str


def decode_password_reset_token(settings: Settings, token: str) -> PasswordResetClaims:
    """Check signature, audience and expiry; raises :class:`InvalidResetToken`."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            audience=_password_reset_audience(settings),
            issuer=settings.jwt_issuer,
            options={"require": ["sub", "exp", "iat", "type", "eml", "pwd"]},
        )
        if payload.get("type") != "password_reset":
            raise InvalidResetToken()
        return PasswordResetClaims(
            user_id=uuid.UUID(payload["sub"]),
            email_fingerprint=str(payload["eml"]),
            password_fingerprint=str(payload["pwd"]),
        )
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise InvalidResetToken() from exc


def _mfa_audience(settings: Settings) -> str:
    return f"{settings.jwt_audience}:mfa"


@dataclass(frozen=True, slots=True)
class MfaChallengeClaims:
    user_id: uuid.UUID
    token_version: int
    jti: str
    # How the first factor was satisfied: "password" or "oauth:<provider>".
    method: str
    expires_at: datetime


def create_mfa_challenge_token(
    settings: Settings, *, user_id: uuid.UUID, token_version: int, method: str
) -> tuple[str, MfaChallengeClaims]:
    """Proof that the first factor passed, redeemable once for tokens plus a TOTP code.

    It grants nothing on its own (its own audience, so it can never act as an access
    token), lives for minutes, and carries ``token_version`` so logout-everywhere or a
    password reset in the meantime kills it.
    """
    now = utcnow()
    claims = MfaChallengeClaims(
        user_id=user_id,
        token_version=token_version,
        jti=uuid.uuid4().hex,
        method=method,
        expires_at=now + timedelta(seconds=settings.mfa_challenge_ttl_seconds),
    )
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "ver": token_version,
        "mth": method,
        "type": "mfa_challenge",
        "iss": settings.jwt_issuer,
        "aud": _mfa_audience(settings),
        "iat": now,
        "exp": claims.expires_at,
        "jti": claims.jti,
    }
    token = jwt.encode(
        payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm
    )
    return token, claims


def decode_mfa_challenge_token(settings: Settings, token: str) -> MfaChallengeClaims:
    """Check signature, audience and expiry; raises :class:`InvalidMfaToken`."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            audience=_mfa_audience(settings),
            issuer=settings.jwt_issuer,
            options={"require": ["sub", "exp", "iat", "type", "ver", "jti", "mth"]},
        )
        if payload.get("type") != "mfa_challenge":
            raise InvalidMfaToken()
        return MfaChallengeClaims(
            user_id=uuid.UUID(payload["sub"]),
            token_version=int(payload["ver"]),
            jti=str(payload["jti"]),
            method=str(payload["mth"]),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
        )
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise InvalidMfaToken() from exc


def decode_access_token(settings: Settings, token: str) -> AccessClaims:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],  # pinned: never trust the header's alg
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["sub", "exp", "iat", "type", "ver", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidToken() from exc
    if payload.get("type") != "access":
        raise InvalidToken()
    try:
        return AccessClaims(
            user_id=uuid.UUID(payload["sub"]),
            role=str(payload.get("role", "")),
            token_version=int(payload["ver"]),
            jti=str(payload["jti"]),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
        )
    except (ValueError, TypeError) as exc:
        raise InvalidToken() from exc
