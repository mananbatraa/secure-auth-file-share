"""Password hashing, JWT access tokens and opaque-token helpers."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pwdlib import PasswordHash

from app.core.config import Settings
from app.core.errors import InvalidToken

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
