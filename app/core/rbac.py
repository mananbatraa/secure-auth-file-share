"""Role-based access control: roles map to a fixed set of permissions."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"


class Permission(StrEnum):
    FILES_UPLOAD = "files:upload"
    FILES_READ_SHARED = "files:read_shared"
    FILES_SHARE = "files:share"
    FILES_MANAGE_ANY = "files:manage_any"
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.GUEST: frozenset({Permission.FILES_READ_SHARED}),
    Role.MEMBER: frozenset(
        {Permission.FILES_READ_SHARED, Permission.FILES_UPLOAD, Permission.FILES_SHARE}
    ),
    Role.ADMIN: frozenset(Permission),
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]
