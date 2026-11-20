from __future__ import annotations

import io

import httpx

from app.core.rbac import Role
from tests.conftest import UserFactory


async def test_member_cannot_list_users(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    member = await make_user()
    r = await client.get("/admin/users", headers=member.headers)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "permission_denied"


async def test_admin_can_list_users(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    await make_user()
    r = await client.get("/admin/users", headers=admin.headers, params={"limit": 10})
    assert r.status_code == 200
    assert {u["email"] for u in r.json()} >= {"admin@example.com", "user2@example.com"}


async def test_role_change_applies_immediately(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    member = await make_user()
    me = (await client.get("/users/me", headers=member.headers)).json()
    r = await client.patch(
        f"/admin/users/{me['id']}", headers=admin.headers, json={"role": "guest"}
    )
    assert r.status_code == 200
    assert r.json()["role"] == "guest"
    # Old token carried the old role: it is invalid now.
    assert (await client.get("/users/me", headers=member.headers)).status_code == 401
    r = await client.post("/auth/refresh", json={"refresh_token": member.refresh_token})
    assert r.status_code == 401
    guest = await make_user.login(member.email)
    upload = await client.post(
        "/files",
        headers=guest.headers,
        files={"upload": ("a.txt", io.BytesIO(b"hi"), "text/plain")},
    )
    assert upload.status_code == 403


async def test_admin_can_deactivate_user(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    member = await make_user()
    me = (await client.get("/users/me", headers=member.headers)).json()
    r = await client.patch(
        f"/admin/users/{me['id']}", headers=admin.headers, json={"is_active": False}
    )
    assert r.status_code == 200
    assert (await client.get("/users/me", headers=member.headers)).status_code == 401


async def test_admin_cannot_demote_self(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    me = (await client.get("/users/me", headers=admin.headers)).json()
    r = await client.patch(
        f"/admin/users/{me['id']}", headers=admin.headers, json={"role": "member"}
    )
    assert r.status_code == 409
    r = await client.patch(
        f"/admin/users/{me['id']}", headers=admin.headers, json={"is_active": False}
    )
    assert r.status_code == 409


async def test_member_cannot_update_users(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    member = await make_user()
    me = (await client.get("/users/me", headers=member.headers)).json()
    r = await client.patch(
        f"/admin/users/{me['id']}", headers=member.headers, json={"role": "admin"}
    )
    assert r.status_code == 403


async def test_update_unknown_user_is_404(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    r = await client.patch(
        "/admin/users/00000000-0000-0000-0000-000000000000",
        headers=admin.headers,
        json={"role": "guest"},
    )
    assert r.status_code == 404
