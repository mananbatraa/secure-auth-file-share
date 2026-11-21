"""Periodic removal of expired rows and the S3 objects they leave behind.

Every sweep works in small batches, each in its own transaction, selected with
``FOR UPDATE SKIP LOCKED``. That keeps lock times short, lets several workers run at
once without blocking each other, and never touches a row a request is holding (for
example an upload intent that :meth:`FileService.complete_direct_upload` has locked).

What gets removed:

* **upload intents** expired for longer than ``cleanup_upload_grace_seconds`` (which is
  always longer than the window in which an expired intent can still be completed), plus
  any object the client managed to upload for them;
* **refresh tokens** expired for longer than ``cleanup_retention_seconds``; until then a
  replayed rotated token is still recognised as reuse and revokes its family;
* **file grants** past their ``expires_at`` (they already grant nothing);
* **share links** expired or revoked for longer than the retention period, so owners can
  still see recently dead links in their listing.

Each sweep that removes something writes one ``maintenance.cleanup`` audit event with the
counts. The audit log itself is append-only and never cleaned here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any

import structlog
from sqlalchemy import Delete, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.security import utcnow
from app.models import FilePermission, RefreshToken, ShareLink, UploadIntent
from app.services.audit import AuditAction, AuditLog
from app.services.storage import ObjectStorage

log = structlog.get_logger(__name__)


@dataclass(slots=True)
class CleanupReport:
    upload_intents: int = 0
    upload_objects: int = 0
    refresh_tokens: int = 0
    file_grants: int = 0
    share_links: int = 0

    @property
    def total_rows(self) -> int:
        return self.upload_intents + self.refresh_tokens + self.file_grants + self.share_links

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


class CleanupService:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        storage: ObjectStorage,
        settings: Settings,
    ) -> None:
        self.sessionmaker = sessionmaker
        self.storage = storage
        self.settings = settings
        self.batch_size = settings.cleanup_batch_size

    async def run_once(self, *, dry_run: bool = False) -> CleanupReport:
        """Run every sweep to completion. With ``dry_run`` only count what would go."""
        report = CleanupReport()
        if dry_run:
            await self._count(report)
        else:
            report.upload_intents, report.upload_objects = await self._sweep_upload_intents()
            report.refresh_tokens = await self._sweep_rows(
                RefreshToken, RefreshToken.expires_at < self._retention_cutoff()
            )
            report.file_grants = await self._sweep_rows(
                FilePermission, FilePermission.expires_at < utcnow()
            )
            report.share_links = await self._sweep_rows(ShareLink, self._dead_link_clause())
            if report.total_rows:
                await self._audit(report)
        log.info("cleanup_finished", dry_run=dry_run, **report.as_dict())
        return report

    # --- sweeps -------------------------------------------------------------------------

    def _retention_cutoff(self) -> Any:
        return utcnow() - timedelta(seconds=self.settings.cleanup_retention_seconds)

    def _dead_link_clause(self) -> Any:
        cutoff = self._retention_cutoff()
        return or_(ShareLink.expires_at < cutoff, ShareLink.revoked_at < cutoff)

    def _intent_cutoff(self) -> Any:
        return utcnow() - timedelta(seconds=self.settings.cleanup_upload_grace_seconds)

    async def _sweep_rows(self, model: Any, clause: Any) -> int:
        removed = 0
        while True:
            async with self.sessionmaker() as session:
                ids = (
                    await session.scalars(
                        select(model.id)
                        .where(clause)
                        .limit(self.batch_size)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                if not ids:
                    return removed
                stmt: Delete = delete(model).where(model.id.in_(ids))
                await session.execute(stmt)
                await session.commit()
            removed += len(ids)
            if len(ids) < self.batch_size:
                return removed

    async def _sweep_upload_intents(self) -> tuple[int, int]:
        """Delete expired intents, then their objects.

        Rows go first: once the row is gone nothing can complete the upload, so deleting
        the object afterwards can never race a completion. If the object delete fails the
        object is orphaned (logged), which is safe: no row points at it.
        """
        rows = objects = 0
        while True:
            async with self.sessionmaker() as session:
                intents = (
                    await session.scalars(
                        select(UploadIntent)
                        .where(UploadIntent.expires_at < self._intent_cutoff())
                        .limit(self.batch_size)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
                if not intents:
                    return rows, objects
                keys = [i.storage_key for i in intents]
                await session.execute(
                    delete(UploadIntent).where(UploadIntent.id.in_([i.id for i in intents]))
                )
                await session.commit()
            rows += len(intents)
            for key in keys:
                try:
                    if await self.storage.head(key) is not None:
                        await self.storage.delete(key)
                        objects += 1
                except Exception:  # keep sweeping; the object is merely orphaned
                    log.exception("cleanup_object_delete_failed", storage_key=key)
            if len(intents) < self.batch_size:
                return rows, objects

    async def _count(self, report: CleanupReport) -> None:
        async with self.sessionmaker() as session:

            async def count(model: Any, clause: Any) -> int:
                return int(
                    await session.scalar(select(func.count()).select_from(model).where(clause)) or 0
                )

            report.upload_intents = await count(
                UploadIntent, UploadIntent.expires_at < self._intent_cutoff()
            )
            report.refresh_tokens = await count(
                RefreshToken, RefreshToken.expires_at < self._retention_cutoff()
            )
            report.file_grants = await count(FilePermission, FilePermission.expires_at < utcnow())
            report.share_links = await count(ShareLink, self._dead_link_clause())

    async def _audit(self, report: CleanupReport) -> None:
        async with self.sessionmaker() as session:
            details: dict[str, Any] = report.as_dict()
            AuditLog(session).record(AuditAction.MAINTENANCE_CLEANUP, **details)
            await session.commit()
