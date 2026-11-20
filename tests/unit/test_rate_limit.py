from __future__ import annotations

import asyncio

import pytest
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis

from app.core.errors import RateLimited, ServiceUnavailable
from app.services.rate_limit import LimitResult, SlidingWindowLimiter


@pytest.fixture
async def limiter() -> SlidingWindowLimiter:
    return SlidingWindowLimiter(FakeAsyncRedis(decode_responses=True))


async def test_allows_up_to_limit_then_blocks(limiter: SlidingWindowLimiter) -> None:
    results = [await limiter.hit("k", limit=3, window_seconds=60) for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]
    assert [r.remaining for r in results[:3]] == [2, 1, 0]
    assert 59 <= results[3].retry_after_seconds <= 60


async def test_keys_are_independent(limiter: SlidingWindowLimiter) -> None:
    await limiter.hit("a", limit=1, window_seconds=60)
    assert (await limiter.hit("b", limit=1, window_seconds=60)).allowed


async def test_window_slides(limiter: SlidingWindowLimiter) -> None:
    assert (await limiter.hit("w", limit=1, window_seconds=1)).allowed
    assert not (await limiter.hit("w", limit=1, window_seconds=1)).allowed
    await asyncio.sleep(1.05)
    assert (await limiter.hit("w", limit=1, window_seconds=1)).allowed


async def test_concurrent_hits_never_exceed_limit(limiter: SlidingWindowLimiter) -> None:
    results = await asyncio.gather(
        *(limiter.hit("c", limit=5, window_seconds=60) for _ in range(25))
    )
    assert sum(r.allowed for r in results) == 5


async def test_enforce_raises_with_retry_after(limiter: SlidingWindowLimiter) -> None:
    await limiter.enforce("e", limit=1, window_seconds=30)
    with pytest.raises(RateLimited) as exc:
        await limiter.enforce("e", limit=1, window_seconds=30)
    assert exc.value.headers is not None
    assert 1 <= int(exc.value.headers["Retry-After"]) <= 30


async def test_reset_clears_key(limiter: SlidingWindowLimiter) -> None:
    await limiter.hit("r", limit=1, window_seconds=60)
    await limiter.reset("r")
    assert (await limiter.hit("r", limit=1, window_seconds=60)).allowed


def _dead_redis() -> Redis:
    return Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.2)


async def test_fails_closed_when_redis_is_down() -> None:
    limiter = SlidingWindowLimiter(_dead_redis(), fail_open=False)
    with pytest.raises(ServiceUnavailable):
        await limiter.hit("x", limit=1, window_seconds=1)


async def test_fails_open_when_configured() -> None:
    limiter = SlidingWindowLimiter(_dead_redis(), fail_open=True)
    assert (await limiter.hit("x", limit=1, window_seconds=1)).allowed
    await limiter.reset("x")  # must not raise either


def test_retry_after_rounds_up() -> None:
    assert LimitResult(False, 0, 1001).retry_after_seconds == 2
    assert LimitResult(False, 0, 0).retry_after_seconds == 1
