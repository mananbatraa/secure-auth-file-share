from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.rbac import ROLE_PERMISSIONS, Permission, Role, has_permission


def test_production_requires_real_jwt_secret() -> None:
    with pytest.raises(ValidationError, match="JWT_SECRET must be set"):
        Settings(environment="production")


def test_production_requires_long_jwt_secret() -> None:
    with pytest.raises(ValidationError, match="at least 32"):
        Settings(environment="production", jwt_secret="short")


def test_production_accepts_strong_secret() -> None:
    s = Settings(environment="production", jwt_secret="x" * 48)
    assert s.environment == "production"


def test_default_download_ttl_cannot_exceed_max() -> None:
    with pytest.raises(ValidationError, match="exceeds"):
        Settings(download_url_default_ttl_seconds=600, download_url_max_ttl_seconds=60)


def test_settings_read_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("S3_BUCKET", "from-env")
    monkeypatch.setenv("LOGIN_MAX_ATTEMPTS_PER_EMAIL", "9")
    s = Settings()
    assert s.s3_bucket == "from-env"
    assert s.login_max_attempts_per_email == 9


def test_admin_has_every_permission() -> None:
    assert ROLE_PERMISSIONS[Role.ADMIN] == frozenset(Permission)


@pytest.mark.parametrize(
    ("role", "permission", "expected"),
    [
        (Role.GUEST, Permission.FILES_READ_SHARED, True),
        (Role.GUEST, Permission.FILES_UPLOAD, False),
        (Role.GUEST, Permission.FILES_SHARE, False),
        (Role.MEMBER, Permission.FILES_UPLOAD, True),
        (Role.MEMBER, Permission.FILES_SHARE, True),
        (Role.MEMBER, Permission.USERS_READ, False),
        (Role.MEMBER, Permission.FILES_MANAGE_ANY, False),
        (Role.ADMIN, Permission.USERS_MANAGE, True),
    ],
)
def test_role_matrix(role: Role, permission: Permission, expected: bool) -> None:
    assert has_permission(role, permission) is expected
