"""TOTP algorithm (RFC 6238 vectors), recovery codes, seed encryption, challenge tokens."""

from __future__ import annotations

import base64
import uuid
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from pydantic import ValidationError

from app.core import totp
from app.core.config import Settings
from app.core.errors import InvalidMfaToken, InvalidToken
from app.core.security import (
    create_access_token,
    create_mfa_challenge_token,
    decode_access_token,
    decode_mfa_challenge_token,
    utcnow,
)

RFC_SECRET = b"12345678901234567890"


@pytest.fixture
def settings() -> Settings:
    return Settings(environment="test", jwt_secret="unit-secret-unit-secret-unit-secret-1")


# RFC 6238 appendix B, SHA1 column (8 digits).
@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_rfc6238_vectors(now: int, expected: str) -> None:
    assert totp.totp(RFC_SECRET, now, digits=8) == expected


def test_rfc4226_hotp_vectors() -> None:
    expected = ["755224", "287082", "359152", "969429", "338314"]
    assert [totp.hotp(RFC_SECRET, i) for i in range(5)] == expected


def test_match_step_accepts_one_step_of_drift_either_way() -> None:
    now = 1_700_000_015.0
    step = totp.time_step(now)
    for offset in (-1, 0, 1):
        code = totp.hotp(RFC_SECRET, step + offset)
        assert totp.match_step(RFC_SECRET, code, now) == step + offset
    assert totp.match_step(RFC_SECRET, totp.hotp(RFC_SECRET, step + 2), now) is None
    assert totp.match_step(RFC_SECRET, totp.hotp(RFC_SECRET, step - 2), now) is None


@pytest.mark.parametrize(
    "code", ["", "12345", "1234567", "abcdef", "12 456", "\uff11\uff12\uff13\uff14\uff15\uff16"]
)
def test_match_step_rejects_malformed_codes(code: str) -> None:
    assert totp.match_step(RFC_SECRET, code, 1_700_000_000.0) is None


def test_new_secret_is_160_bits_and_base32_has_no_padding() -> None:
    secret = totp.new_secret()
    assert len(secret) == 20
    b32 = totp.secret_to_base32(secret)
    assert "=" not in b32
    assert base64.b32decode(b32) == secret
    assert totp.new_secret() != secret


def test_provisioning_uri_for_authenticator_apps() -> None:
    uri = totp.provisioning_uri(RFC_SECRET, account="ann@example.com", issuer="Secure Share")
    parsed = urlparse(uri)
    assert parsed.scheme == "otpauth"
    assert parsed.netloc == "totp"
    assert parsed.path == "/Secure%20Share:ann@example.com"
    q = parse_qs(parsed.query)
    assert q["secret"] == [totp.secret_to_base32(RFC_SECRET)]
    assert q["issuer"] == ["Secure Share"]
    assert q["digits"] == ["6"]
    assert q["period"] == ["30"]
    assert q["algorithm"] == ["SHA1"]


def test_recovery_codes_are_readable_and_unique() -> None:
    codes = {totp.new_recovery_code() for _ in range(200)}
    assert len(codes) == 200
    for code in codes:
        left, right = code.split("-")
        assert len(left) == len(right) == 5
        assert not set(left + right) & set("01ilo")


def test_recovery_code_hash_normalizes_input_and_is_bound_to_the_user(
    settings: Settings,
) -> None:
    user = uuid.uuid4()
    h = totp.hash_recovery_code(settings, user, "abcde-fghjk")
    assert totp.hash_recovery_code(settings, user, " ABCDE FGHJK ") == h
    assert totp.hash_recovery_code(settings, user, "abcdefghjk") == h
    assert totp.hash_recovery_code(settings, uuid.uuid4(), "abcde-fghjk") != h
    other = Settings(environment="test", jwt_secret="another-secret-another-secret-12345")
    assert totp.hash_recovery_code(other, user, "abcde-fghjk") != h


def test_secret_encryption_roundtrip_and_binding(settings: Settings) -> None:
    user = uuid.uuid4()
    secret = totp.new_secret()
    stored = totp.encrypt_secret(settings, user, secret)
    assert stored.startswith("v1:")
    assert totp.secret_to_base32(secret) not in stored
    assert totp.encrypt_secret(settings, user, secret) != stored  # random nonce
    assert totp.decrypt_secret(settings, user, stored) == secret
    with pytest.raises(ValueError, match="decrypt"):
        totp.decrypt_secret(settings, uuid.uuid4(), stored)  # copied to another user
    tampered = stored[:-4] + ("AAAA" if stored[-4:] != "AAAA" else "BBBB")
    with pytest.raises(ValueError, match="decrypt"):
        totp.decrypt_secret(settings, user, tampered)
    with pytest.raises(ValueError, match="format"):
        totp.decrypt_secret(settings, user, "v0:abc")


def test_dedicated_encryption_key_is_used_when_set(settings: Settings) -> None:
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    keyed = Settings(environment="test", jwt_secret=settings.jwt_secret, mfa_encryption_key=key)
    user = uuid.uuid4()
    stored = totp.encrypt_secret(keyed, user, b"s" * 20)
    assert totp.decrypt_secret(keyed, user, stored) == b"s" * 20
    with pytest.raises(ValueError, match="decrypt"):
        totp.decrypt_secret(settings, user, stored)  # derived-from-JWT key differs


@pytest.mark.parametrize("key", ["not base64 !!", base64.urlsafe_b64encode(b"short").decode()])
def test_bad_encryption_key_is_rejected(key: str) -> None:
    with pytest.raises(ValidationError, match="MFA_ENCRYPTION_KEY"):
        Settings(environment="test", mfa_encryption_key=key)


def test_challenge_token_roundtrip(settings: Settings) -> None:
    user = uuid.uuid4()
    token, claims = create_mfa_challenge_token(
        settings, user_id=user, token_version=3, method="oauth:github"
    )
    decoded = decode_mfa_challenge_token(settings, token)
    assert decoded.user_id == user
    assert decoded.token_version == 3
    assert decoded.method == "oauth:github"
    assert decoded.jti == claims.jti


def test_challenge_and_access_tokens_are_not_interchangeable(settings: Settings) -> None:
    challenge, _ = create_mfa_challenge_token(
        settings, user_id=uuid.uuid4(), token_version=0, method="password"
    )
    with pytest.raises(InvalidToken):
        decode_access_token(settings, challenge)
    access, _ = create_access_token(settings, user_id=uuid.uuid4(), role="member", token_version=0)
    with pytest.raises(InvalidMfaToken):
        decode_mfa_challenge_token(settings, access)


def _forge(settings: Settings, **overrides: object) -> str:
    now = utcnow()
    payload: dict[str, object] = {
        "sub": str(uuid.uuid4()),
        "ver": 0,
        "mth": "password",
        "type": "mfa_challenge",
        "iss": settings.jwt_issuer,
        "aud": f"{settings.jwt_audience}:mfa",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": "x",
    }
    payload.update(overrides)
    return jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm="HS256")


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": utcnow() - timedelta(seconds=1)},
        {"type": "access"},
        {"sub": "not-a-uuid"},
        {"ver": "x"},
    ],
)
def test_bad_challenge_tokens_are_rejected(
    settings: Settings, overrides: dict[str, object]
) -> None:
    with pytest.raises(InvalidMfaToken):
        decode_mfa_challenge_token(settings, _forge(settings, **overrides))


def test_empty_encryption_key_means_unset() -> None:
    assert Settings(environment="test", mfa_encryption_key="").mfa_encryption_key is None
