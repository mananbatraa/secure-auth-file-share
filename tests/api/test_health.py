from __future__ import annotations

import httpx
from redis.asyncio import Redis

from app.resources import Resources


async def test_healthz(client: httpx.AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_readyz_all_ok(client: httpx.AsyncClient) -> None:
    r = await client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["checks"] == {"database": "ok", "redis": "ok", "storage": "ok"}


async def test_readyz_reports_degraded_dependency(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    resources.redis = Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.2)
    r = await client.get("/readyz")
    assert r.status_code == 503
    assert r.json()["checks"]["redis"] == "error"
    assert r.json()["checks"]["database"] == "ok"


async def test_openapi_lists_core_routes(client: httpx.AsyncClient) -> None:
    paths = (await client.get("/openapi.json")).json()["paths"]
    for p in ["/auth/login", "/auth/refresh", "/files", "/files/{file_id}/links", "/s/{token}"]:
        assert p in paths
