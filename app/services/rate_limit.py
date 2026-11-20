"""Sliding-window-log rate limiter backed by a Redis sorted set.

The whole check-and-record runs in one Lua script, so concurrent requests can't both
squeeze past the limit, and Redis ``TIME`` is the clock, so API replicas with skewed
clocks still agree.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.errors import RateLimited, ServiceUnavailable

log = structlog.get_logger(__name__)

_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local window_ms = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local member = ARGV[3]
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window_ms)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry_ms = window_ms
  if oldest[2] then
    retry_ms = window_ms - (now - tonumber(oldest[2]))
  end
  return {0, 0, retry_ms}
end
redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window_ms)
return {1, limit - count - 1, 0}
"""


@dataclass(frozen=True, slots=True)
class LimitResult:
    allowed: bool
    remaining: int
    retry_after_ms: int

    @property
    def retry_after_seconds(self) -> int:
        return max(1, -(-self.retry_after_ms // 1000))


class SlidingWindowLimiter:
    def __init__(self, redis: Redis, *, prefix: str = "rl", fail_open: bool = False) -> None:
        self._redis = redis
        self._prefix = prefix
        self._fail_open = fail_open
        self._script = redis.register_script(_SLIDING_WINDOW_LUA)

    def _key(self, name: str) -> str:
        return f"{self._prefix}:{name}"

    async def hit(self, name: str, *, limit: int, window_seconds: int) -> LimitResult:
        try:
            raw = await self._script(
                keys=[self._key(name)],
                args=[window_seconds * 1000, limit, secrets.token_hex(8)],
            )
        except RedisError as exc:
            log.warning("rate_limiter_unavailable", key=name, fail_open=self._fail_open)
            if self._fail_open:
                return LimitResult(allowed=True, remaining=limit, retry_after_ms=0)
            raise ServiceUnavailable("Rate limiter unavailable") from exc
        allowed, remaining, retry_ms = (int(x) for x in raw)
        return LimitResult(allowed=bool(allowed), remaining=remaining, retry_after_ms=retry_ms)

    async def enforce(self, name: str, *, limit: int, window_seconds: int) -> LimitResult:
        result = await self.hit(name, limit=limit, window_seconds=window_seconds)
        if not result.allowed:
            raise RateLimited(result.retry_after_seconds)
        return result

    async def reset(self, name: str) -> None:
        try:
            await self._redis.delete(self._key(name))
        except RedisError:
            log.warning("rate_limiter_reset_failed", key=name)
