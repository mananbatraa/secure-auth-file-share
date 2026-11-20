"""End-to-end wiring: the real lifespan builds its own DB pool, real Redis and S3 client."""

from __future__ import annotations

import os
import uuid

import httpx
import pytest
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import Settings
from app.main import create_app
from app.models import AuditEvent
from app.resources import Resources
from app.services.rate_limit import SlidingWindowLimiter
from tests.conftest import PASSWORD, TABLES

REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/15")


@pytest.fixture
async def real_redis() -> Redis:
    r = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        await r.ping()
    except RedisError:
        pytest.skip("real Redis not available (set TEST_REDIS_URL)")
    await r.flushdb()
    return r


async def test_lifespan_wires_real_dependencies(
    settings: Settings, engine: AsyncEngine, real_redis: Redis
) -> None:
    cfg = settings.model_copy(
        update={
            "redis_url": REDIS_URL,
            "s3_bucket": f"lifespan-{uuid.uuid4().hex[:8]}",
            "s3_create_bucket": True,
            "cors_origins": ["https://app.example.com"],
            "trust_proxy_headers": True,
        }
    )
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            ready = await client.get("/readyz")
            assert ready.status_code == 200, ready.text
            pre = await client.options(
                "/auth/login",
                headers={
                    "Origin": "https://app.example.com",
                    "Access-Control-Request-Method": "POST",
                },
            )
            assert pre.headers["access-control-allow-origin"] == "https://app.example.com"
            email = f"{uuid.uuid4().hex[:8]}@example.com"
            r = await client.post("/auth/register", json={"email": email, "password": PASSWORD})
            assert r.status_code == 201
            r = await client.post(
                "/auth/login",
                json={"email": email, "password": PASSWORD},
                headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1"},
            )
            assert r.status_code == 200
            # With trusted proxy headers the client IP comes from X-Forwarded-For.
            assert await real_redis.exists("rl:login:ip:203.0.113.7")
        resources: Resources = app.state.resources
        async with resources.sessionmaker() as s:
            login = await s.scalar(select(AuditEvent).where(AuditEvent.action == "auth.login"))
        assert login is not None
        assert login.ip_address == "203.0.113.7"
    # Resources the app built itself are closed on shutdown.
    assert resources.http.is_closed
    await real_redis.flushdb()
    await real_redis.aclose()
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {TABLES} CASCADE"))


async def test_limiter_is_atomic_on_real_redis(real_redis: Redis) -> None:
    import asyncio

    limiter = SlidingWindowLimiter(real_redis, prefix=f"t{uuid.uuid4().hex[:6]}")
    results = await asyncio.gather(
        *(limiter.hit("burst", limit=10, window_seconds=60) for _ in range(100))
    )
    assert sum(r.allowed for r in results) == 10
    blocked = [r for r in results if not r.allowed]
    assert all(1 <= r.retry_after_seconds <= 60 for r in blocked)
    await real_redis.flushdb()
    await real_redis.aclose()
