"""Long-lived process resources (DB pool, Redis, S3 client, HTTP client)."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.db.session import create_engine, create_sessionmaker
from app.services.rate_limit import SlidingWindowLimiter
from app.services.storage import ObjectStorage


@dataclass
class Resources:
    settings: Settings
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    redis: Redis
    storage: ObjectStorage
    http: httpx.AsyncClient
    limiter: SlidingWindowLimiter

    @classmethod
    def build(
        cls,
        settings: Settings,
        *,
        redis: Redis | None = None,
        http: httpx.AsyncClient | None = None,
        storage: ObjectStorage | None = None,
    ) -> Resources:
        engine = create_engine(settings)
        redis = redis or Redis.from_url(settings.redis_url, decode_responses=True)
        return cls(
            settings=settings,
            engine=engine,
            sessionmaker=create_sessionmaker(engine),
            redis=redis,
            storage=storage or ObjectStorage(settings),
            http=http or httpx.AsyncClient(timeout=httpx.Timeout(10.0)),
            limiter=SlidingWindowLimiter(redis, fail_open=settings.rate_limit_fail_open),
        )

    async def aclose(self) -> None:
        await self.http.aclose()
        await self.redis.aclose()
        await self.engine.dispose()
