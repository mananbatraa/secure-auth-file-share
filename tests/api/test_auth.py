from __future__ import annotations

import asyncio
from datetime import timedelta

import httpx
from sqlalchemy import func, select, update

from app.core.security import utcnow
from app.models import RefreshToken, User
from app.resources import Resources
from tests.conftest import PASSWORD, UserFactory


async def test_register_returns_user_without_secrets(client: httpx.AsyncClient) -> None:
    r = await client.post(
        "/auth/register", json={"email": "Alice@Example.COM", "password": PASSWORD}
    )
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert body["role"] == "member"
    assert "hashed_password" not in body
    assert "password" not in body


async def test_register_duplicate_email_is_case_insensitive(client: httpx.AsyncClient) -> None:
    await client.post("/auth/register", json={"email": "bob@example.com", "password": PASSWORD})
    r = await client.post("/auth/register", json={"email": "BOB@example.com", "password": PASSWORD})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "conflict"


async def test_register_rejects_weak_passwords(client: httpx.AsyncClient) -> None:
    for pw in ["short", " padded-password-here ", "carol-is-my-password"]:
        r = await client.post("/auth/register", json={"email": "carol@example.com", "password": pw})
        assert r.status_code == 422, pw


async def test_register_rejects_invalid_email(client: httpx.AsyncClient) -> None:
    r = await client.post("/auth/register", json={"email": "nope", "password": PASSWORD})
    assert r.status_code == 422


async def test_login_and_me(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    user = await make_user("dave@example.com")
    r = await client.get("/users/me", headers=user.headers)
    assert r.status_code == 200
    assert r.json()["email"] == "dave@example.com"


async def test_login_wrong_password_and_unknown_user_look_identical(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    await make_user("erin@example.com")
    wrong = await client.post(
        "/auth/login", json={"email": "erin@example.com", "password": "x" * 20}
    )
    unknown = await client.post(
        "/auth/login", json={"email": "nobody@example.com", "password": "x" * 20}
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert wrong.headers["www-authenticate"] == "Bearer"


async def test_protected_routes_need_a_valid_token(client: httpx.AsyncClient) -> None:
    assert (await client.get("/users/me")).status_code == 401
    r = await client.get("/users/me", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_token"


async def test_refresh_token_is_not_an_access_token(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user()
    r = await client.get("/users/me", headers={"Authorization": f"Bearer {user.refresh_token}"})
    assert r.status_code == 401


async def test_refresh_rotates_tokens(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    user = await make_user()
    r = await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert r.status_code == 200
    pair = r.json()
    assert pair["refresh_token"] != user.refresh_token
    assert pair["token_type"] == "bearer"
    me = await client.get("/users/me", headers={"Authorization": f"Bearer {pair['access_token']}"})
    assert me.status_code == 200
    # The new refresh token keeps working.
    r2 = await client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert r2.status_code == 200


async def test_reusing_a_rotated_refresh_token_revokes_the_family(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    first = (await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})).json()

    # Attacker replays the stolen, already-rotated token.
    replay = await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "refresh_token_reused"

    # The legitimate client's current token is now dead too.
    legit = await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert legit.status_code == 401
    assert legit.json()["error"]["code"] == "refresh_token_reused"

    async with resources.sessionmaker() as s:
        live = await s.scalar(
            select(func.count()).select_from(RefreshToken).where(RefreshToken.revoked_at.is_(None))
        )
    assert live == 0


async def test_reuse_only_revokes_that_session(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user()
    other_session = await make_user.login(user.email)
    await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})  # reuse
    r = await client.post("/auth/refresh", json={"refresh_token": other_session.refresh_token})
    assert r.status_code == 200


async def test_concurrent_refresh_with_same_token_succeeds_once(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user()
    responses = await asyncio.gather(
        *(
            client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
            for _ in range(5)
        )
    )
    codes = sorted(r.status_code for r in responses)
    # Row lock serialises them: one wins, the rest look like replays.
    assert codes == [200, 401, 401, 401, 401]
    winner = next(r for r in responses if r.status_code == 200).json()
    # A concurrent duplicate is treated as reuse, so even the winner's new token is revoked.
    r = await client.post("/auth/refresh", json={"refresh_token": winner["refresh_token"]})
    assert r.status_code == 401


async def test_unknown_and_expired_refresh_tokens_are_rejected(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    r = await client.post("/auth/refresh", json={"refresh_token": "x" * 43})
    assert r.status_code == 401
    user = await make_user()
    async with resources.sessionmaker() as s:
        await s.execute(update(RefreshToken).values(expires_at=utcnow() - timedelta(seconds=1)))
        await s.commit()
    r = await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_token"


async def test_logout_revokes_refresh_token(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user()
    assert (
        await client.post("/auth/logout", json={"refresh_token": user.refresh_token})
    ).status_code == 204
    # Idempotent.
    assert (
        await client.post("/auth/logout", json={"refresh_token": user.refresh_token})
    ).status_code == 204
    r = await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert r.status_code == 401


async def test_logout_all_kills_access_tokens_immediately(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user()
    second = await make_user.login(user.email)
    assert (await client.post("/auth/logout-all", headers=user.headers)).status_code == 204
    assert (await client.get("/users/me", headers=user.headers)).status_code == 401
    assert (await client.get("/users/me", headers=second.headers)).status_code == 401
    r = await client.post("/auth/refresh", json={"refresh_token": second.refresh_token})
    assert r.status_code == 401
    fresh = await make_user.login(user.email)
    assert (await client.get("/users/me", headers=fresh.headers)).status_code == 200


async def test_change_password(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    user = await make_user()
    new = "a-brand-new-long-passphrase"
    bad = await client.post(
        "/auth/change-password",
        headers=user.headers,
        json={"current_password": "wrong-password!!", "new_password": new},
    )
    assert bad.status_code == 401
    ok = await client.post(
        "/auth/change-password",
        headers=user.headers,
        json={"current_password": PASSWORD, "new_password": new},
    )
    assert ok.status_code == 204
    assert (await client.get("/users/me", headers=user.headers)).status_code == 401
    old = await client.post("/auth/login", json={"email": user.email, "password": PASSWORD})
    assert old.status_code == 401
    r = await client.post("/auth/login", json={"email": user.email, "password": new})
    assert r.status_code == 200


async def test_deactivated_user_cannot_login_or_refresh(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    async with resources.sessionmaker() as s:
        await s.execute(update(User).values(is_active=False))
        await s.commit()
    assert (await client.get("/users/me", headers=user.headers)).status_code == 401
    r = await client.post("/auth/login", json={"email": user.email, "password": PASSWORD})
    assert r.status_code == 401
    r = await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert r.status_code == 401


async def test_refresh_records_client_metadata(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    await make_user()
    async with resources.sessionmaker() as s:
        row = await s.scalar(select(RefreshToken))
    assert row is not None
    assert row.ip_address == "127.0.0.1"
    assert row.user_agent is not None
    assert "python-httpx" in row.user_agent


async def test_security_headers_present(client: httpx.AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "x-request-id" in r.headers
    r = await client.get("/healthz", headers={"X-Request-ID": "abc"})
    assert r.headers["x-request-id"] == "abc"
