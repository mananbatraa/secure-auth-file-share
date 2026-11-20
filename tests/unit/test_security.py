from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import Settings
from app.core.errors import InvalidToken
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_opaque_token,
    hash_password,
    new_opaque_token,
    verify_password,
)

SETTINGS = Settings(environment="test", jwt_secret="u" * 64)


def _secret() -> str:
    return SETTINGS.jwt_secret.get_secret_value()


def test_password_hash_roundtrip() -> None:
    hashed = hash_password("a long passphrase")
    assert hashed.startswith("$argon2id$")
    assert verify_password("a long passphrase", hashed)
    assert not verify_password("wrong", hashed)


def test_verify_password_without_hash_is_false() -> None:
    assert verify_password("anything", None) is False


def test_opaque_tokens_are_random_and_hashed() -> None:
    a, b = new_opaque_token(), new_opaque_token()
    assert a != b
    assert len(a) >= 40
    assert hash_opaque_token(a) == hash_opaque_token(a)
    assert len(hash_opaque_token(a)) == 64


def test_access_token_roundtrip() -> None:
    uid = uuid.uuid4()
    token, exp = create_access_token(SETTINGS, user_id=uid, role="member", token_version=3)
    claims = decode_access_token(SETTINGS, token)
    assert claims.user_id == uid
    assert claims.role == "member"
    assert claims.token_version == 3
    assert abs((claims.expires_at - exp).total_seconds()) < 1


def _payload(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    base: dict[str, object] = {
        "sub": str(uuid.uuid4()),
        "role": "member",
        "ver": 0,
        "type": "access",
        "iss": SETTINGS.jwt_issuer,
        "aud": SETTINGS.jwt_audience,
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": "x",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": datetime.now(UTC) - timedelta(seconds=5)},
        {"aud": "someone-else"},
        {"iss": "evil"},
        {"type": "refresh"},
        {"ver": None},
        {"sub": "not-a-uuid"},
    ],
    ids=["expired", "audience", "issuer", "wrong-type", "missing-version", "bad-subject"],
)
def test_rejects_invalid_claims(overrides: dict[str, object]) -> None:
    token = jwt.encode(_payload(**overrides), _secret(), algorithm="HS256")
    with pytest.raises(InvalidToken):
        decode_access_token(SETTINGS, token)


def test_rejects_wrong_signature() -> None:
    token = jwt.encode(_payload(), "another-secret-another-secret-12345", algorithm="HS256")
    with pytest.raises(InvalidToken):
        decode_access_token(SETTINGS, token)


def test_rejects_alg_none() -> None:
    token = jwt.encode(_payload(), None, algorithm="none")  # type: ignore[arg-type]
    with pytest.raises(InvalidToken):
        decode_access_token(SETTINGS, token)


def test_rejects_algorithm_substitution() -> None:
    token = jwt.encode(_payload(), _secret(), algorithm="HS512")
    with pytest.raises(InvalidToken):
        decode_access_token(SETTINGS, token)


def test_rejects_garbage() -> None:
    with pytest.raises(InvalidToken):
        decode_access_token(SETTINGS, "not.a.jwt")
