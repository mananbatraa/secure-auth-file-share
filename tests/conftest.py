"""Shared fixtures.

Integration tests run against a real Postgres (``TEST_DATABASE_URL``), a fake Redis
(fakeredis with Lua support), and a real S3 API served by moto on a local port, so
presigned URLs are actually fetched over HTTP.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path

import boto3
import httpx
import pytest
from fakeredis import FakeAsyncRedis
from moto.server import ThreadedMotoServer
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings
from app.core.rbac import Role
from app.main import create_app
from app.models import User
from app.resources import Resources
from app.services.rate_limit import SlidingWindowLimiter
from app.services.storage import ObjectStorage

ROOT = Path(__file__).resolve().parent.parent
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/fileshare_test"
)
PASSWORD = "correct-horse-battery-staple"
TABLES = "audit_events, share_links, file_permissions, files, refresh_tokens, oauth_accounts, users"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def run_alembic(*args: str, database_url: str = TEST_DATABASE_URL) -> None:
    subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT,
        env={**os.environ, "DATABASE_URL": database_url},
        check=True,
        capture_output=True,
    )


@pytest.fixture(scope="session")
def s3_endpoint() -> Iterator[str]:
    port = _free_port()
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=port, verbose=False)
    server.start()
    yield f"http://127.0.0.1:{port}"
    server.stop()


@pytest.fixture(scope="session")
def settings(s3_endpoint: str) -> Settings:
    return Settings(
        environment="test",
        database_url=TEST_DATABASE_URL,
        jwt_secret="test-secret-test-secret-test-secret-123",
        s3_endpoint_url=s3_endpoint,
        s3_bucket="test-bucket",
        s3_access_key_id="testing",
        s3_secret_access_key="testing",
        max_upload_bytes=1024 * 1024,
        github_client_id="gh-client",
        github_client_secret="gh-secret",
        google_client_id="google-client",
        google_client_secret="google-secret",
        oauth_redirect_base_url="http://testserver",
    )


@pytest.fixture(scope="session")
def _migrated_db() -> None:
    """Build the schema through Alembic, so every test run also exercises the migrations."""

    async def _reset() -> None:
        engine = create_async_engine(TEST_DATABASE_URL)
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
        await engine.dispose()

    import asyncio

    asyncio.run(_reset())
    run_alembic("upgrade", "head")


@pytest.fixture(scope="session")
async def engine(_migrated_db: None) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(TEST_DATABASE_URL, pool_size=20)
    yield eng
    await eng.dispose()


@pytest.fixture(scope="session")
def storage(settings: Settings) -> ObjectStorage:
    store = ObjectStorage(settings)
    boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    ).create_bucket(Bucket=settings.s3_bucket)
    return store


@pytest.fixture
async def redis() -> AsyncIterator[FakeAsyncRedis]:
    r = FakeAsyncRedis(decode_responses=True)
    yield r
    await r.flushall()
    await r.aclose()


@pytest.fixture
async def resources(
    settings: Settings, engine: AsyncEngine, redis: FakeAsyncRedis, storage: ObjectStorage
) -> AsyncIterator[Resources]:
    http = httpx.AsyncClient()
    res = Resources(
        settings=settings,
        engine=engine,
        sessionmaker=async_sessionmaker(engine, expire_on_commit=False),
        redis=redis,
        storage=storage,
        http=http,
        limiter=SlidingWindowLimiter(redis, fail_open=settings.rate_limit_fail_open),
    )
    yield res
    await http.aclose()
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {TABLES} CASCADE"))


@pytest.fixture
async def session(resources: Resources) -> AsyncIterator[AsyncSession]:
    async with resources.sessionmaker() as s:
        yield s


@pytest.fixture
async def client(resources: Resources) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(resources=resources)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@dataclass
class TestUser:
    __test__ = False

    id: str
    email: str
    access_token: str
    refresh_token: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}


class UserFactory:
    def __init__(self, client: httpx.AsyncClient, resources: Resources) -> None:
        self.client = client
        self.resources = resources
        self._n = 0

    async def __call__(self, email: str | None = None, *, role: Role = Role.MEMBER) -> TestUser:
        self._n += 1
        email = email or f"user{self._n}@example.com"
        r = await self.client.post("/auth/register", json={"email": email, "password": PASSWORD})
        assert r.status_code == 201, r.text
        user_id = r.json()["id"]
        if role != Role.MEMBER:
            async with self.resources.sessionmaker() as s:
                await s.execute(update(User).where(User.email == email).values(role=role))
                await s.commit()
        return await self.login(email, user_id)

    async def login(self, email: str, user_id: str = "") -> TestUser:
        r = await self.client.post("/auth/login", json={"email": email, "password": PASSWORD})
        assert r.status_code == 200, r.text
        body = r.json()
        return TestUser(user_id, email, body["access_token"], body["refresh_token"])


@pytest.fixture
def make_user(client: httpx.AsyncClient, resources: Resources) -> UserFactory:
    return UserFactory(client, resources)
