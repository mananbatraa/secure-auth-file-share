"""Background cleanup: expired intents (and their objects), tokens, grants and links."""

from __future__ import annotations

import asyncio
import io
import uuid
from datetime import datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import cleanup as cleanup_cli
from app.core.config import Settings
from app.core.security import hash_opaque_token, utcnow
from app.models import (
    AccessLevel,
    AuditEvent,
    FilePermission,
    RefreshToken,
    ShareLink,
    StoredFile,
    UploadIntent,
    User,
)
from app.resources import Resources
from app.services.cleanup import CleanupReport, CleanupService
from app.services.storage import ObjectStorage
from tests.conftest import UserFactory

HOUR = timedelta(hours=1)
DAY = timedelta(days=1)


def service(resources: Resources, **overrides: Any) -> CleanupService:
    settings = resources.settings.model_copy(update=overrides)
    return CleanupService(resources.sessionmaker, resources.storage, settings)


async def new_user(session: AsyncSession) -> User:
    user = User(email=f"{uuid.uuid4().hex}@example.com", hashed_password="x")
    session.add(user)
    await session.flush()
    return user


async def new_file(session: AsyncSession, owner: User) -> StoredFile:
    f = StoredFile(
        owner_id=owner.id,
        filename="a.txt",
        content_type="text/plain",
        size_bytes=1,
        sha256="0" * 64,
        storage_key=f"files/{owner.id}/{uuid.uuid4()}",
    )
    session.add(f)
    await session.flush()
    return f


async def new_intent(
    resources: Resources, session: AsyncSession, owner: User, expires_at: datetime, *, upload: bool
) -> UploadIntent:
    intent_id = uuid.uuid4()
    key = f"files/{owner.id}/{intent_id}"
    intent = UploadIntent(
        id=intent_id,
        owner_id=owner.id,
        storage_key=key,
        filename="clip.mp4",
        content_type="video/mp4",
        size_bytes=4,
        expires_at=expires_at,
    )
    session.add(intent)
    if upload:
        await resources.storage.upload(key, io.BytesIO(b"data"), content_type="video/mp4")
    return intent


def new_token(owner: User, expires_at: datetime) -> RefreshToken:
    return RefreshToken(
        user_id=owner.id,
        family_id=uuid.uuid4(),
        token_hash=hash_opaque_token(uuid.uuid4().hex),
        expires_at=expires_at,
    )


def new_link(
    file: StoredFile, expires_at: datetime, revoked_at: datetime | None = None
) -> ShareLink:
    return ShareLink(
        file_id=file.id,
        token_hash=hash_opaque_token(uuid.uuid4().hex),
        expires_at=expires_at,
        revoked_at=revoked_at,
    )


async def count(resources: Resources, model: Any) -> int:
    async with resources.sessionmaker() as s:
        return int(await s.scalar(select(func.count()).select_from(model)) or 0)


async def cleanup_events(resources: Resources) -> list[AuditEvent]:
    async with resources.sessionmaker() as s:
        rows = await s.scalars(select(AuditEvent).where(AuditEvent.action == "maintenance.cleanup"))
        return list(rows)


async def test_expired_upload_intents_and_their_objects_are_removed(
    resources: Resources,
) -> None:
    now = utcnow()
    async with resources.sessionmaker() as s:
        owner = await new_user(s)
        stale_uploaded = await new_intent(resources, s, owner, now - 2 * HOUR, upload=True)
        stale_empty = await new_intent(resources, s, owner, now - 2 * HOUR, upload=False)
        # Expired, but still inside the grace window: may yet be completed.
        recent = await new_intent(resources, s, owner, now - timedelta(minutes=10), upload=True)
        live = await new_intent(resources, s, owner, now + HOUR, upload=False)
        await s.commit()

    report = await service(resources).run_once()

    assert report.upload_intents == 2
    assert report.upload_objects == 1
    async with resources.sessionmaker() as s:
        left = set(await s.scalars(select(UploadIntent.id)))
    assert left == {recent.id, live.id}
    assert await resources.storage.head(stale_uploaded.storage_key) is None
    assert await resources.storage.head(stale_empty.storage_key) is None
    assert await resources.storage.head(recent.storage_key) is not None


async def test_a_cleaned_up_upload_can_no_longer_be_completed(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    r = await client.post(
        "/files/uploads",
        headers=user.headers,
        json={"filename": "a.bin", "content_type": "application/octet-stream", "size_bytes": 4},
    )
    assert r.status_code == 201, r.text
    upload_id = r.json()["upload_id"]
    async with resources.sessionmaker() as s:
        intent = await s.get(UploadIntent, uuid.UUID(upload_id))
        assert intent is not None
        intent.expires_at = utcnow() - 2 * HOUR
        await s.commit()

    await service(resources).run_once()

    r = await client.post(f"/files/uploads/{upload_id}/complete", headers=user.headers)
    assert r.status_code == 404


async def test_refresh_tokens_are_kept_for_the_retention_period(resources: Resources) -> None:
    now = utcnow()
    async with resources.sessionmaker() as s:
        owner = await new_user(s)
        old = new_token(owner, now - 8 * DAY)
        recently_expired = new_token(owner, now - DAY)
        live = new_token(owner, now + DAY)
        s.add_all([old, recently_expired, live])
        await s.commit()

    report = await service(resources).run_once()

    assert report.refresh_tokens == 1
    async with resources.sessionmaker() as s:
        left = set(await s.scalars(select(RefreshToken.id)))
    assert left == {recently_expired.id, live.id}


async def test_rotation_chains_survive_partial_deletion(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    """Deleting an old token that a newer one replaced must not break the newer one."""
    user = await make_user()
    r = await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert r.status_code == 200
    new_refresh = r.json()["refresh_token"]
    async with resources.sessionmaker() as s:
        first = await s.scalar(
            select(RefreshToken).where(
                RefreshToken.token_hash == hash_opaque_token(user.refresh_token)
            )
        )
        assert first is not None
        assert first.replaced_by_id is not None
        first.expires_at = utcnow() - 30 * DAY
        await s.commit()

    assert (await service(resources).run_once()).refresh_tokens == 1

    r = await client.post("/auth/refresh", json={"refresh_token": new_refresh})
    assert r.status_code == 200


async def test_expired_grants_are_removed(resources: Resources) -> None:
    now = utcnow()
    async with resources.sessionmaker() as s:
        owner, a, b, c = [await new_user(s) for _ in range(4)]
        f = await new_file(s, owner)
        expired = FilePermission(
            file_id=f.id, user_id=a.id, level=AccessLevel.VIEWER, expires_at=now - HOUR
        )
        forever = FilePermission(file_id=f.id, user_id=b.id, level=AccessLevel.EDITOR)
        future = FilePermission(
            file_id=f.id, user_id=c.id, level=AccessLevel.VIEWER, expires_at=now + HOUR
        )
        s.add_all([expired, forever, future])
        await s.commit()

    report = await service(resources).run_once()

    assert report.file_grants == 1
    async with resources.sessionmaker() as s:
        left = set(await s.scalars(select(FilePermission.id)))
    assert left == {forever.id, future.id}


async def test_dead_share_links_are_removed_after_retention(resources: Resources) -> None:
    now = utcnow()
    async with resources.sessionmaker() as s:
        owner = await new_user(s)
        f = await new_file(s, owner)
        long_expired = new_link(f, now - 8 * DAY)
        long_revoked = new_link(f, now + DAY, revoked_at=now - 8 * DAY)
        recently_expired = new_link(f, now - DAY)
        recently_revoked = new_link(f, now + DAY, revoked_at=now - HOUR)
        live = new_link(f, now + DAY)
        s.add_all([long_expired, long_revoked, recently_expired, recently_revoked, live])
        await s.commit()

    report = await service(resources).run_once()

    assert report.share_links == 2
    async with resources.sessionmaker() as s:
        left = set(await s.scalars(select(ShareLink.id)))
    assert left == {recently_expired.id, recently_revoked.id, live.id}


async def test_zero_retention_removes_everything_dead(resources: Resources) -> None:
    now = utcnow()
    async with resources.sessionmaker() as s:
        owner = await new_user(s)
        f = await new_file(s, owner)
        s.add_all([new_token(owner, now - HOUR), new_link(f, now - HOUR)])
        await s.commit()

    report = await service(resources, cleanup_retention_seconds=0).run_once()

    assert (report.refresh_tokens, report.share_links) == (1, 1)


async def test_sweeps_work_through_many_batches(resources: Resources) -> None:
    now = utcnow()
    async with resources.sessionmaker() as s:
        owner = await new_user(s)
        s.add_all([new_token(owner, now - 30 * DAY) for _ in range(7)])
        for _ in range(5):
            await new_intent(resources, s, owner, now - DAY, upload=True)
        await s.commit()

    report = await service(resources, cleanup_batch_size=2).run_once()

    assert report.refresh_tokens == 7
    assert (report.upload_intents, report.upload_objects) == (5, 5)
    assert await count(resources, RefreshToken) == 0
    assert await count(resources, UploadIntent) == 0


async def test_rows_locked_by_a_request_are_skipped_not_waited_on(resources: Resources) -> None:
    now = utcnow()
    async with resources.sessionmaker() as s:
        owner = await new_user(s)
        locked = await new_intent(resources, s, owner, now - DAY, upload=True)
        free = await new_intent(resources, s, owner, now - DAY, upload=True)
        await s.commit()

    async with resources.sessionmaker() as holder:
        # What complete_direct_upload holds while it verifies the object.
        await holder.scalar(
            select(UploadIntent).where(UploadIntent.id == locked.id).with_for_update()
        )
        report = await asyncio.wait_for(service(resources).run_once(), timeout=10)
        await holder.rollback()

    assert report.upload_intents == 1
    async with resources.sessionmaker() as s:
        assert set(await s.scalars(select(UploadIntent.id))) == {locked.id}
    assert await resources.storage.head(free.storage_key) is None
    assert await resources.storage.head(locked.storage_key) is not None

    # The next sweep picks it up once the lock is released.
    assert (await service(resources).run_once()).upload_intents == 1


async def test_object_delete_failures_do_not_stop_the_sweep(
    resources: Resources, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = utcnow()
    async with resources.sessionmaker() as s:
        owner = await new_user(s)
        for _ in range(2):
            await new_intent(resources, s, owner, now - DAY, upload=True)
        s.add(new_token(owner, now - 30 * DAY))
        await s.commit()

    async def broken_delete(key: str) -> None:
        raise RuntimeError("S3 is down")

    monkeypatch.setattr(resources.storage, "delete", broken_delete)
    report = await service(resources).run_once()

    assert (report.upload_intents, report.upload_objects) == (2, 0)
    assert report.refresh_tokens == 1
    assert await count(resources, UploadIntent) == 0


async def test_dry_run_counts_without_deleting_or_auditing(resources: Resources) -> None:
    now = utcnow()
    async with resources.sessionmaker() as s:
        owner, other = await new_user(s), await new_user(s)
        f = await new_file(s, owner)
        await new_intent(resources, s, owner, now - DAY, upload=True)
        s.add_all(
            [
                new_token(owner, now - 30 * DAY),
                new_link(f, now - 30 * DAY),
                FilePermission(
                    file_id=f.id, user_id=other.id, level=AccessLevel.VIEWER, expires_at=now - HOUR
                ),
            ]
        )
        await s.commit()

    report = await service(resources).run_once(dry_run=True)

    assert report.as_dict() == {
        "upload_intents": 1,
        "upload_objects": 0,
        "refresh_tokens": 1,
        "file_grants": 1,
        "share_links": 1,
    }
    for model in (UploadIntent, RefreshToken, ShareLink, FilePermission):
        assert await count(resources, model) == 1
    assert await cleanup_events(resources) == []


async def test_each_productive_sweep_is_audited_once(resources: Resources) -> None:
    async with resources.sessionmaker() as s:
        owner = await new_user(s)
        s.add_all([new_token(owner, utcnow() - 30 * DAY) for _ in range(3)])
        await s.commit()

    await service(resources).run_once()
    await service(resources).run_once()  # nothing left: no event

    events = await cleanup_events(resources)
    assert len(events) == 1
    assert events[0].actor_id is None
    assert events[0].outcome == "success"
    assert events[0].details["refresh_tokens"] == 3
    assert events[0].details["upload_intents"] == 0


def test_report_totals() -> None:
    report = CleanupReport(upload_intents=1, upload_objects=9, refresh_tokens=2, share_links=3)
    assert report.total_rows == 6


def test_grace_period_must_outlast_the_completion_window(settings: Settings) -> None:
    with pytest.raises(ValueError, match="cleanup_upload_grace_seconds"):
        Settings(**{**settings.model_dump(), "cleanup_upload_grace_seconds": 60})


# --- worker entry point ---------------------------------------------------------------


async def test_worker_once_sweeps_and_exits_zero(
    resources: Resources, storage: ObjectStorage
) -> None:
    async with resources.sessionmaker() as s:
        owner = await new_user(s)
        s.add(new_token(owner, utcnow() - 30 * DAY))
        await s.commit()

    code = await cleanup_cli.run(resources.settings, once=True, storage=storage)

    assert code == 0
    assert await count(resources, RefreshToken) == 0


async def test_worker_once_exits_nonzero_when_the_sweep_fails(
    settings: Settings, storage: ObjectStorage
) -> None:
    broken = settings.model_copy(
        update={"database_url": "postgresql+asyncpg://postgres:postgres@127.0.0.1:1/none"}
    )
    assert await cleanup_cli.run(broken, once=True, storage=storage) == 1


async def test_worker_loop_keeps_sweeping_until_stopped(
    resources: Resources, storage: ObjectStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop = asyncio.Event()
    sweeps = 0
    original = CleanupService.run_once

    async def counting(self: CleanupService, *, dry_run: bool = False) -> CleanupReport:
        nonlocal sweeps
        sweeps += 1
        if sweeps == 2:
            raise RuntimeError("transient failure")  # logged, loop carries on
        if sweeps == 3:
            stop.set()
        return await original(self, dry_run=dry_run)

    monkeypatch.setattr(CleanupService, "run_once", counting)
    code = await asyncio.wait_for(
        cleanup_cli.run(resources.settings, once=False, interval=1, stop=stop, storage=storage),
        timeout=15,
    )

    assert code == 0
    assert sweeps == 3


def test_cli_arguments() -> None:
    args = cleanup_cli.parse_args(["--once", "--dry-run", "--interval", "30"])
    assert (args.once, args.dry_run, args.interval) == (True, True, 30)
    defaults = cleanup_cli.parse_args([])
    assert (defaults.once, defaults.dry_run, defaults.interval) == (False, False, None)
    with pytest.raises(SystemExit):
        cleanup_cli.parse_args(["--interval", "0"])
