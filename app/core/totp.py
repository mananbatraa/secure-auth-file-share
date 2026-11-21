"""TOTP (RFC 6238) one-time passwords, recovery codes, and secret encryption at rest.

Implemented on the standard library (plus ``cryptography`` for AES-GCM), so the
algorithm is small enough to read and is checked against the RFC 6238 test vectors.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import Settings

DIGITS = 6
PERIOD_SECONDS = 30
SECRET_BYTES = 20  # 160 bits, the RFC 4226 recommendation for HMAC-SHA1
# Accept the previous and next 30 s step, for clock skew and typing time.
DRIFT_STEPS = 1

# No 0/o, 1/l/i: recovery codes get typed from paper.
_RECOVERY_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
RECOVERY_CODE_LENGTH = 10  # ~49.5 bits each
_CIPHER_VERSION = "v1"


# --- TOTP ------------------------------------------------------------------------------
def new_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def secret_to_base32(secret: bytes) -> str:
    """The form authenticator apps expect (RFC 4648 base32, padding stripped)."""
    return base64.b32encode(secret).decode().rstrip("=")


def hotp(secret: bytes, counter: int, *, digits: int = DIGITS, digest: str = "sha1") -> str:
    """RFC 4226 HOTP with dynamic truncation."""
    mac = hmac.new(secret, counter.to_bytes(8, "big"), digest).digest()
    offset = mac[-1] & 0x0F
    value = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFF_FFFF
    return str(value % 10**digits).zfill(digits)


def time_step(now: float, *, period: int = PERIOD_SECONDS) -> int:
    return int(now) // period


def totp(secret: bytes, now: float, *, digits: int = DIGITS, digest: str = "sha1") -> str:
    return hotp(secret, time_step(now), digits=digits, digest=digest)


def match_step(secret: bytes, code: str, now: float, *, drift: int = DRIFT_STEPS) -> int | None:
    """Return the time step ``code`` is valid for (within the drift window), or None.

    Every candidate is compared in constant time and the loop never exits early, so
    timing doesn't reveal which step matched. The caller rejects steps it has already
    accepted, which makes each code single-use.
    """
    if len(code) != DIGITS or not code.isascii() or not code.isdigit():
        return None
    current = time_step(now)
    matched: int | None = None
    for step in range(current - drift, current + drift + 1):
        if hmac.compare_digest(hotp(secret, step), code) and matched is None:
            matched = step
    return matched


def provisioning_uri(secret: bytes, *, account: str, issuer: str) -> str:
    """The ``otpauth://`` URI that authenticator apps import (usually as a QR code)."""
    label = quote(f"{issuer}:{account}", safe="@:")
    query = urlencode(
        {
            "secret": secret_to_base32(secret),
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": PERIOD_SECONDS,
        },
        quote_via=quote,
    )
    return f"otpauth://totp/{label}?{query}"


# --- recovery codes --------------------------------------------------------------------
def new_recovery_code() -> str:
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(RECOVERY_CODE_LENGTH))
    half = RECOVERY_CODE_LENGTH // 2
    return f"{raw[:half]}-{raw[half:]}"


def normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in code.lower() if ch not in " -\t")


def hash_recovery_code(settings: Settings, user_id: uuid.UUID, code: str) -> str:
    """Keyed and bound to the user: a leaked table row is useless on its own."""
    key = _derive_key(settings, b"safs:recovery-code")
    msg = user_id.bytes + normalize_recovery_code(code).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# --- secret encryption at rest ---------------------------------------------------------
def _derive_key(settings: Settings, info: bytes) -> bytes:
    if settings.mfa_encryption_key is not None:
        master = base64.urlsafe_b64decode(settings.mfa_encryption_key.get_secret_value())
    else:
        master = settings.jwt_secret.get_secret_value().encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(master)


def encrypt_secret(settings: Settings, user_id: uuid.UUID, secret: bytes) -> str:
    """AES-256-GCM with the user id as associated data.

    A database dump alone doesn't yield usable TOTP seeds, and a ciphertext copied onto
    another user's row fails to decrypt.
    """
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(_derive_key(settings, b"safs:totp-secret")).encrypt(
        nonce, secret, user_id.bytes
    )
    return f"{_CIPHER_VERSION}:{base64.urlsafe_b64encode(nonce + sealed).decode()}"


def decrypt_secret(settings: Settings, user_id: uuid.UUID, stored: str) -> bytes:
    """Raises ``ValueError`` if the value is malformed or fails authentication."""
    version, _, payload = stored.partition(":")
    if version != _CIPHER_VERSION or not payload:
        raise ValueError("unknown TOTP secret format")
    blob = base64.urlsafe_b64decode(payload)
    try:
        return AESGCM(_derive_key(settings, b"safs:totp-secret")).decrypt(
            blob[:12], blob[12:], user_id.bytes
        )
    except Exception as exc:  # InvalidTag: wrong key, wrong user, or tampering
        raise ValueError("TOTP secret failed to decrypt") from exc
