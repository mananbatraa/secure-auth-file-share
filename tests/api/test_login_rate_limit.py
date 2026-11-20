from __future__ import annotations

import httpx

from app.resources import Resources
from tests.conftest import PASSWORD, UserFactory


async def _attempt(
    client: httpx.AsyncClient, email: str, password: str, ip: str | None = None
) -> httpx.Response:
    headers = {"X-Forwarded-For": ip} if ip else {}
    return await client.post(
        "/auth/login", json={"email": email, "password": password}, headers=headers
    )


async def test_account_is_throttled_after_too_many_attempts(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    limit = resources.settings.login_max_attempts_per_email
    for _ in range(limit - 1):  # make_user already logged in once (and reset the bucket)
        assert (await _attempt(client, user.email, "wrong-password!!")).status_code == 401
    assert (await _attempt(client, user.email, "wrong-password!!")).status_code == 401
    blocked = await _attempt(client, user.email, PASSWORD)
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limited"
    retry_after = int(blocked.headers["retry-after"])
    assert 1 <= retry_after <= resources.settings.login_window_seconds


async def test_email_key_is_normalised(client: httpx.AsyncClient, resources: Resources) -> None:
    limit = resources.settings.login_max_attempts_per_email
    for i in range(limit):
        email = "Victim@Example.com" if i % 2 else "victim@example.com"
        assert (await _attempt(client, email, "wrong-password!!")).status_code == 401
    assert (await _attempt(client, "VICTIM@example.com", "x" * 20)).status_code == 429


async def test_successful_login_resets_account_bucket(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    limit = resources.settings.login_max_attempts_per_email
    for _ in range(limit - 1):
        await _attempt(client, user.email, "wrong-password!!")
    assert (await _attempt(client, user.email, PASSWORD)).status_code == 200
    for _ in range(limit - 1):
        assert (await _attempt(client, user.email, "wrong-password!!")).status_code == 401


async def test_ip_bucket_stops_password_spraying(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    limit = resources.settings.login_max_attempts_per_ip
    for i in range(limit):
        r = await _attempt(client, f"target{i}@example.com", "Spring2026!!")
        assert r.status_code == 401
    r = await _attempt(client, "another@example.com", "Spring2026!!")
    assert r.status_code == 429


async def test_forwarded_for_is_ignored_unless_trusted(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    assert resources.settings.trust_proxy_headers is False
    limit = resources.settings.login_max_attempts_per_ip
    # Rotating a spoofed X-Forwarded-For must not mint fresh IP buckets.
    for i in range(limit):
        await _attempt(client, f"t{i}@example.com", "x" * 20, ip=f"10.0.0.{i}")
    r = await _attempt(client, "last@example.com", "x" * 20, ip="10.9.9.9")
    assert r.status_code == 429


async def test_login_fails_closed_when_redis_is_down(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    from redis.asyncio import Redis

    from app.services.rate_limit import SlidingWindowLimiter

    resources.limiter = SlidingWindowLimiter(
        Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.2), fail_open=False
    )
    r = await _attempt(client, "x@example.com", "y" * 20)
    assert r.status_code == 503
