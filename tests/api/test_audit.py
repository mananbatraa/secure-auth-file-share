"""The audit trail: what gets recorded, that it is append-only, and the admin query API."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError

from app.core.rbac import Role
from app.core.security import utcnow
from app.models import AuditEvent, User
from app.resources import Resources
from tests.api.test_files import upload
from tests.api.test_oauth import _start, mock_github
from tests.conftest import PASSWORD, TestUser, UserFactory


async def events(resources: Resources, action: str | None = None) -> list[AuditEvent]:
    async with resources.sessionmaker() as s:
        stmt = select(AuditEvent).order_by(AuditEvent.id)
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        return list(await s.scalars(stmt))


async def audit_api(client: httpx.AsyncClient, admin: TestUser, **params: Any) -> dict[str, Any]:
    r = await client.get("/admin/audit", headers=admin.headers, params=params)
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


# --- what gets recorded ------------------------------------------------------------------
async def test_register_and_login_are_recorded_with_client_context(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    r = await client.post(
        "/auth/register", json={"email": "auditee@example.com", "password": PASSWORD}
    )
    user_id = r.json()["id"]
    r = await client.post(
        "/auth/login",
        json={"email": "auditee@example.com", "password": PASSWORD},
        headers={"User-Agent": "audit-test/1.0", "X-Request-ID": "req-123"},
    )
    assert r.status_code == 200
    reg, login = await events(resources)
    assert (reg.action, reg.outcome, str(reg.actor_id)) == ("auth.register", "success", user_id)
    assert (login.action, login.outcome, str(login.actor_id)) == ("auth.login", "success", user_id)
    assert login.user_agent == "audit-test/1.0"
    assert login.request_id == "req-123"
    assert login.ip_address == "127.0.0.1"


async def test_failed_logins_are_recorded_even_though_the_request_fails(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user("victim@example.com")
    bad = await client.post(
        "/auth/login", json={"email": "Victim@example.com", "password": "wrong-password-123"}
    )
    unknown = await client.post(
        "/auth/login", json={"email": "ghost@example.com", "password": "wrong-password-123"}
    )
    # The client sees identical errors; only the audit trail tells them apart.
    assert bad.status_code == unknown.status_code == 401
    assert bad.json() == unknown.json()
    failures = [e for e in await events(resources, "auth.login") if e.outcome == "failure"]
    assert [(str(e.actor_id) if e.actor_id else None, e.details) for e in failures] == [
        (user.id, {"email": "victim@example.com", "reason": "bad_password"}),
        (None, {"email": "ghost@example.com", "reason": "unknown_email"}),
    ]


async def test_inactive_login_reason_is_recorded(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    await make_user("gone@example.com")
    async with resources.sessionmaker() as s:
        await s.execute(update(User).values(is_active=False))
        await s.commit()
    r = await client.post("/auth/login", json={"email": "gone@example.com", "password": PASSWORD})
    assert r.status_code == 401
    (event,) = [e for e in await events(resources, "auth.login") if e.outcome == "failure"]
    assert event.details["reason"] == "inactive"


async def test_throttled_logins_are_recorded(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    limit = resources.settings.login_max_attempts_per_email
    for _ in range(limit + 1):
        r = await client.post(
            "/auth/login", json={"email": "target@example.com", "password": "nope-nope-nope"}
        )
    assert r.status_code == 429
    (event,) = await events(resources, "auth.login_throttled")
    assert event.outcome == "failure"
    assert event.details == {"email": "target@example.com"}


async def test_refresh_token_reuse_is_recorded(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    r = await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert r.status_code == 200
    replay = await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert replay.status_code == 401
    (event,) = await events(resources, "auth.refresh_reuse_detected")
    assert event.outcome == "failure"
    assert str(event.actor_id) == user.id
    assert event.target_type == "token_family"


async def test_session_and_password_events(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    await client.post("/auth/logout", json={"refresh_token": user.refresh_token})
    user = await make_user.login(user.email, user.id)
    wrong = await client.post(
        "/auth/change-password",
        headers=user.headers,
        json={"current_password": "not-my-password", "new_password": "brand-new-passphrase-9"},
    )
    assert wrong.status_code == 401
    ok = await client.post(
        "/auth/change-password",
        headers=user.headers,
        json={"current_password": PASSWORD, "new_password": "brand-new-passphrase-9"},
    )
    assert ok.status_code == 204
    actions = [(e.action, e.outcome) for e in await events(resources) if e.action != "auth.login"]
    assert actions == [
        ("auth.register", "success"),
        ("auth.logout", "success"),
        ("auth.password_changed", "failure"),
        ("auth.password_changed", "success"),
    ]


async def test_logout_all_is_recorded(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    r = await client.post("/auth/logout-all", headers=user.headers)
    assert r.status_code == 204
    (event,) = await events(resources, "auth.logout_all")
    assert str(event.actor_id) == user.id


async def test_admin_role_change_records_the_admin_and_the_diff(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    member = await make_user()
    r = await client.patch(
        f"/admin/users/{member.id}",
        headers=admin.headers,
        json={"role": "guest", "is_active": False},
    )
    assert r.status_code == 200
    (event,) = await events(resources, "admin.user_updated")
    assert str(event.actor_id) == admin.id
    assert event.target_id == member.id
    assert event.details == {
        "changes": {
            "role": {"from": "member", "to": "guest"},
            "is_active": {"from": True, "to": False},
        }
    }
    # The forced sign-out is part of the admin action, not a separate user logout.
    assert await events(resources, "auth.logout_all") == []


async def test_no_op_admin_update_records_nothing(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    member = await make_user()
    r = await client.patch(
        f"/admin/users/{member.id}", headers=admin.headers, json={"role": "member"}
    )
    assert r.status_code == 200
    assert await events(resources, "admin.user_updated") == []


async def test_oauth_login_is_recorded(client: httpx.AsyncClient, resources: Resources) -> None:
    q = await _start(client, "github")
    with respx.mock(assert_all_called=True) as router:
        mock_github(router)
        r = await client.get(
            "/auth/oauth/github/callback", params={"code": "abc", "state": q["state"][0]}
        )
    assert r.status_code == 200
    (event,) = await events(resources, "auth.oauth_login")
    assert event.details == {"provider": "github"}


async def test_file_lifecycle_is_fully_audited(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner = await make_user()
    friend = await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    await client.patch(f"/files/{file_id}", headers=owner.headers, json={"filename": "q4.txt"})
    await client.post(
        f"/files/{file_id}/permissions", headers=owner.headers, json={"email": friend.email}
    )
    await client.get(f"/files/{file_id}/download", headers=friend.headers)
    await client.delete(f"/files/{file_id}/permissions/{friend.id}", headers=owner.headers)
    link = (await client.post(f"/files/{file_id}/links", headers=owner.headers, json={})).json()
    assert (await client.get(f"/s/{link['token']}")).status_code == 307
    await client.delete(f"/files/{file_id}/links/{link['id']}", headers=owner.headers)
    assert (await client.get(f"/s/{link['token']}")).status_code == 410
    assert (await client.get("/s/not-a-real-token")).status_code == 404
    await client.delete(f"/files/{file_id}", headers=owner.headers)

    trail = [e for e in await events(resources) if e.action.startswith("file.")]
    assert [(e.action, e.outcome) for e in trail] == [
        ("file.uploaded", "success"),
        ("file.renamed", "success"),
        ("file.grant_created", "success"),
        ("file.download_url_issued", "success"),
        ("file.grant_revoked", "success"),
        ("file.link_created", "success"),
        ("file.link_redeemed", "success"),
        ("file.link_revoked", "success"),
        ("file.link_rejected", "failure"),
        ("file.link_rejected", "failure"),
        ("file.deleted", "success"),
    ]
    by_action = {e.action: e for e in trail}
    assert by_action["file.renamed"].details == {"old": "report.txt", "new": "q4.txt"}
    assert by_action["file.grant_created"].details["grantee_id"] == friend.id
    assert by_action["file.grant_created"].details["level"] == "viewer"
    assert str(by_action["file.download_url_issued"].actor_id) == friend.id
    assert by_action["file.download_url_issued"].details["access"] == "viewer"
    # Anonymous redemption: no actor, but the link and file are traceable.
    redeemed = by_action["file.link_redeemed"]
    assert redeemed.actor_id is None
    assert (redeemed.target_id, redeemed.details["file_id"]) == (link["id"], file_id)
    gone, unknown = [e for e in trail if e.action == "file.link_rejected"]
    assert gone.target_id == link["id"]
    assert gone.details == {"reason": "expired_revoked_or_exhausted"}
    assert unknown.target_id is None
    assert unknown.details == {"reason": "unknown_token"}
    # The trail outlives the file it describes.
    assert by_action["file.uploaded"].target_id == file_id


async def test_failed_action_rolls_back_its_audit_event(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    await make_user("dup@example.com")
    r = await client.post("/auth/register", json={"email": "DUP@example.com", "password": PASSWORD})
    assert r.status_code == 409
    assert len(await events(resources, "auth.register")) == 1


async def test_audit_rows_survive_user_deletion(
    make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    async with resources.sessionmaker() as s:
        await s.execute(delete(User).where(User.id == uuid.UUID(user.id)))
        await s.commit()
    assert {str(e.actor_id) for e in await events(resources)} == {user.id}


# --- append-only ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "stmt",
    [
        "UPDATE audit_events SET outcome = 'success'",
        "DELETE FROM audit_events",
    ],
)
async def test_audit_rows_cannot_be_modified(
    make_user: UserFactory, resources: Resources, stmt: str
) -> None:
    await make_user()
    async with resources.sessionmaker() as s:
        with pytest.raises(DBAPIError, match="append-only"):
            await s.execute(text(stmt))
        await s.rollback()
    assert len(await events(resources)) == 2


# --- admin API -----------------------------------------------------------------------------
async def test_audit_api_requires_admin(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    member = await make_user()
    assert (await client.get("/admin/audit")).status_code == 401
    assert (await client.get("/admin/audit", headers=member.headers)).status_code == 403


async def test_audit_api_lists_newest_first_and_paginates(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    for _ in range(3):
        await make_user()
    everything = await audit_api(client, admin, limit=200)
    ids = [e["id"] for e in everything["items"]]
    assert ids == sorted(ids, reverse=True)
    assert everything["next_before_id"] is None

    seen: list[int] = []
    cursor: int | None = None
    while True:
        page = await audit_api(client, admin, limit=3, **({"before_id": cursor} if cursor else {}))
        seen += [e["id"] for e in page["items"]]
        cursor = page["next_before_id"]
        if cursor is None:
            break
        assert len(page["items"]) == 3
    assert seen == ids


async def test_audit_api_filters(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    member = await make_user()
    file_id = (await upload(client, member)).json()["id"]
    await client.post("/auth/login", json={"email": member.email, "password": "wrong-pass-123"})

    def actions(page: dict[str, Any]) -> list[str]:
        return [e["action"] for e in page["items"]]

    assert actions(await audit_api(client, admin, action="file.uploaded")) == ["file.uploaded"]
    assert set(actions(await audit_api(client, admin, action="auth."))) == {
        "auth.register",
        "auth.login",
    }
    failures = await audit_api(client, admin, outcome="failure")
    assert actions(failures) == ["auth.login"]
    assert failures["items"][0]["details"]["reason"] == "bad_password"
    mine = await audit_api(client, admin, actor_id=member.id)
    assert {e["actor_id"] for e in mine["items"]} == {member.id}
    by_target = await audit_api(client, admin, target_type="file", target_id=file_id)
    assert actions(by_target) == ["file.uploaded"]
    # LIKE wildcards in a prefix filter are matched literally.
    assert actions(await audit_api(client, admin, action="%.")) == []
    assert actions(await audit_api(client, admin, action="auth_.")) == []


async def test_audit_api_time_window(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    now = utcnow()
    past = await audit_api(client, admin, until=(now - timedelta(hours=1)).isoformat())
    assert past["items"] == []
    recent = await audit_api(client, admin, since=(now - timedelta(hours=1)).isoformat())
    assert len(recent["items"]) == 2
    future = await audit_api(client, admin, since=(now + timedelta(hours=1)).isoformat())
    assert future["items"] == []


async def test_audit_api_validates_input(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    for params in ({"limit": 0}, {"limit": 201}, {"before_id": 0}, {"outcome": "maybe"}):
        r = await client.get("/admin/audit", headers=admin.headers, params=params)
        assert r.status_code == 422, params
