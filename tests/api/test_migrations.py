"""Migrations must build the same schema as the ORM models, and be reversible."""

from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.db.base import Base
from tests.conftest import TEST_DATABASE_URL, run_alembic


def _diff(conn: Connection) -> list[object]:
    ctx = MigrationContext.configure(conn, opts={"compare_type": True})
    return list(compare_metadata(ctx, Base.metadata))


async def test_models_match_migrations(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        diff = await conn.run_sync(_diff)
    assert diff == []


@pytest.fixture
async def scratch_db_url() -> object:
    admin = create_async_engine(TEST_DATABASE_URL, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text("DROP DATABASE IF EXISTS fileshare_migrations"))
        await conn.execute(text("CREATE DATABASE fileshare_migrations"))
    url = TEST_DATABASE_URL.rsplit("/", 1)[0] + "/fileshare_migrations"
    yield url
    async with admin.connect() as conn:
        await conn.execute(text("DROP DATABASE IF EXISTS fileshare_migrations WITH (FORCE)"))
    await admin.dispose()


async def test_upgrade_downgrade_roundtrip(scratch_db_url: str) -> None:
    run_alembic("upgrade", "head", database_url=scratch_db_url)
    run_alembic("downgrade", "base", database_url=scratch_db_url)
    eng = create_async_engine(scratch_db_url)
    async with eng.connect() as conn:
        tables = (
            (await conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'")))
            .scalars()
            .all()
        )
        enums = (
            (await conn.execute(text("SELECT typname FROM pg_type WHERE typtype='e'")))
            .scalars()
            .all()
        )
    await eng.dispose()
    assert set(tables) <= {"alembic_version"}
    assert enums == []
    run_alembic("upgrade", "head", database_url=scratch_db_url)
