"""File storage, per-file permissions and anonymous share links."""

from __future__ import annotations

import hashlib
import re
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import IO

import structlog
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import (
    Conflict,
    Gone,
    NotFound,
    PayloadTooLarge,
    PermissionDenied,
    ValidationFailed,
)
from app.core.rbac import Permission, has_permission
from app.core.security import hash_opaque_token, new_opaque_token, utcnow
from app.models import AccessLevel, FilePermission, ShareLink, StoredFile, UploadIntent, User
from app.services.audit import AuditAction, AuditLog, Outcome
from app.services.auth import normalize_email
from app.services.storage import ObjectStorage, PresignedPost

log = structlog.get_logger(__name__)

_CHUNK = 1024 * 1024
_CONTENT_TYPE_RE = re.compile(r"^[\w.+-]+/[\w.+-]+$")


def sanitize_filename(name: str | None) -> str:
    """Keep the display name harmless: no paths, control chars, or absurd lengths."""
    name = unicodedata.normalize("NFC", name or "")
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C").strip(" .")
    if not name:
        return "untitled"
    if len(name) > 255:
        stem, dot, ext = name.rpartition(".")
        name = (stem[: 254 - len(ext)] + dot + ext) if dot and len(ext) <= 16 else name[:255]
    return name


def sanitize_content_type(value: str | None) -> str:
    value = (value or "").split(";", 1)[0].strip().lower()
    return value if _CONTENT_TYPE_RE.match(value) else "application/octet-stream"


@dataclass(frozen=True, slots=True)
class FileWithAccess:
    file: StoredFile
    access: AccessLevel


@dataclass(frozen=True, slots=True)
class DirectUpload:
    intent: UploadIntent
    post: PresignedPost


@dataclass(frozen=True, slots=True)
class GrantWithEmail:
    grant: FilePermission
    email: str


class FileService:
    def __init__(
        self,
        session: AsyncSession,
        storage: ObjectStorage,
        settings: Settings,
        audit: AuditLog | None = None,
    ) -> None:
        self.session = session
        self.storage = storage
        self.settings = settings
        self.audit = audit or AuditLog(session)

    # --- access control -----------------------------------------------------------------
    async def access_level(self, user: User, file: StoredFile) -> AccessLevel | None:
        if file.owner_id == user.id:
            return AccessLevel.OWNER
        if has_permission(user.role, Permission.FILES_MANAGE_ANY):
            return AccessLevel.OWNER
        if not has_permission(user.role, Permission.FILES_READ_SHARED):
            return None
        grant = await self.session.scalar(
            select(FilePermission).where(
                FilePermission.file_id == file.id,
                FilePermission.user_id == user.id,
                or_(FilePermission.expires_at.is_(None), FilePermission.expires_at > utcnow()),
            )
        )
        return grant.level if grant else None

    async def get_for(
        self, user: User, file_id: uuid.UUID, required: AccessLevel
    ) -> FileWithAccess:
        file = await self.session.get(StoredFile, file_id)
        level = await self.access_level(user, file) if file else None
        # 404 rather than 403 when the caller can't see the file at all: don't confirm it exists.
        if file is None or level is None:
            raise NotFound("File not found")
        if level.rank < required.rank:
            raise PermissionDenied()
        return FileWithAccess(file, level)

    # --- files --------------------------------------------------------------------------
    async def upload(
        self, owner: User, stream: IO[bytes], *, filename: str | None, content_type: str | None
    ) -> StoredFile:
        if not has_permission(owner.role, Permission.FILES_UPLOAD):
            raise PermissionDenied("Your role cannot upload files")
        file_id = uuid.uuid4()
        key = f"files/{owner.id}/{file_id}"
        digest = hashlib.sha256()
        size = 0
        # Copy to a spooled temp file while hashing and enforcing the size limit, so an
        # oversized upload is rejected before anything reaches object storage.
        with tempfile.SpooledTemporaryFile(max_size=8 * _CHUNK) as buf:
            while chunk := stream.read(_CHUNK):
                size += len(chunk)
                if size > self.settings.max_upload_bytes:
                    raise PayloadTooLarge(
                        f"File exceeds the {self.settings.max_upload_bytes} byte limit"
                    )
                digest.update(chunk)
                buf.write(chunk)
            if size == 0:
                raise ValidationFailed("File is empty")
            buf.seek(0)
            ctype = sanitize_content_type(content_type)
            await self.storage.upload(key, buf, content_type=ctype)

        record = StoredFile(
            id=file_id,
            owner_id=owner.id,
            filename=sanitize_filename(filename),
            content_type=ctype,
            size_bytes=size,
            sha256=digest.hexdigest(),
            storage_key=key,
        )
        self.session.add(record)
        self.audit.record(
            AuditAction.FILE_UPLOADED,
            actor_id=owner.id,
            target_type="file",
            target_id=file_id,
            size_bytes=size,
            sha256=record.sha256,
        )
        try:
            await self.session.commit()
        except Exception:
            await self.session.rollback()
            await self.storage.delete(key)  # don't leave orphaned objects behind
            raise
        log.info("file_uploaded", file_id=str(file_id), owner_id=str(owner.id), size=size)
        return record

    # --- direct-to-S3 uploads -----------------------------------------------------------
    async def start_direct_upload(
        self,
        owner: User,
        *,
        filename: str,
        content_type: str | None,
        size_bytes: int,
        sha256: str | None,
    ) -> DirectUpload:
        """Reserve a key and hand back a presigned POST pinned to its size and type."""
        if not has_permission(owner.role, Permission.FILES_UPLOAD):
            raise PermissionDenied("Your role cannot upload files")
        if size_bytes > self.settings.direct_upload_max_bytes:
            raise PayloadTooLarge(
                f"File exceeds the {self.settings.direct_upload_max_bytes} byte limit"
            )
        upload_id = uuid.uuid4()
        ttl = self.settings.upload_intent_ttl_seconds
        intent = UploadIntent(
            id=upload_id,
            owner_id=owner.id,
            storage_key=f"files/{owner.id}/{upload_id}",
            filename=sanitize_filename(filename),
            content_type=sanitize_content_type(content_type),
            size_bytes=size_bytes,
            sha256=sha256.lower() if sha256 else None,
            expires_at=utcnow() + timedelta(seconds=ttl),
        )
        post = self.storage.presigned_upload(
            intent.storage_key,
            content_type=intent.content_type,
            size_bytes=size_bytes,
            sha256=intent.sha256,
            ttl_seconds=ttl,
        )
        self.session.add(intent)
        await self.session.commit()
        return DirectUpload(intent, post)

    async def complete_direct_upload(self, owner: User, upload_id: uuid.UUID) -> StoredFile:
        """Verify what actually landed in S3, then turn the intent into a file.

        Nothing the client did is trusted: size, content type and checksum are re-checked
        against the object itself, and a mismatching object is deleted.
        """
        intent = await self.session.scalar(
            select(UploadIntent)
            .where(UploadIntent.id == upload_id, UploadIntent.owner_id == owner.id)
            .with_for_update()
        )
        if intent is None:
            raise NotFound("Upload not found")
        key = intent.storage_key
        # The policy expires with the intent, so an object can only arrive before then;
        # allow completing a little later so a slow last request can still be confirmed.
        if intent.expires_at + timedelta(minutes=5) < utcnow():
            await self._discard_intent(intent, owner, "expired")
            raise Gone("This upload has expired; start a new one")
        info = await self.storage.head(key)
        if info is None:
            await self.session.rollback()
            raise ValidationFailed("No object has been uploaded yet")
        if info.size_bytes != intent.size_bytes:
            await self._discard_intent(intent, owner, "size_mismatch")
            raise ValidationFailed("Uploaded object does not match the declared size")
        if (info.content_type or "").split(";", 1)[0].strip().lower() != intent.content_type:
            await self._discard_intent(intent, owner, "content_type_mismatch")
            raise ValidationFailed("Uploaded object does not match the declared content type")
        digest = info.sha256 or await self.storage.sha256(key)
        if intent.sha256 and digest != intent.sha256:
            await self._discard_intent(intent, owner, "checksum_mismatch")
            raise ValidationFailed("Uploaded object does not match the declared SHA-256")

        record = StoredFile(
            id=intent.id,
            owner_id=owner.id,
            filename=intent.filename,
            content_type=intent.content_type,
            size_bytes=info.size_bytes,
            sha256=digest,
            storage_key=key,
        )
        await self.session.delete(intent)
        self.session.add(record)
        self.audit.record(
            AuditAction.FILE_UPLOADED,
            actor_id=owner.id,
            target_type="file",
            target_id=record.id,
            size_bytes=record.size_bytes,
            sha256=digest,
            method="direct",
        )
        await self.session.commit()
        log.info("file_uploaded", file_id=str(record.id), owner_id=str(owner.id), direct=True)
        return record

    async def _discard_intent(self, intent: UploadIntent, owner: User, reason: str) -> None:
        key, upload_id = intent.storage_key, intent.id
        await self.session.delete(intent)
        self.audit.record(
            AuditAction.FILE_UPLOAD_REJECTED,
            outcome=Outcome.FAILURE,
            actor_id=owner.id,
            target_type="upload",
            target_id=upload_id,
            reason=reason,
        )
        await self.session.commit()
        await self.storage.delete(key)

    async def list_for(self, user: User, scope: str) -> list[FileWithAccess]:
        results: list[FileWithAccess] = []
        if scope in ("owned", "all"):
            owned = await self.session.scalars(
                select(StoredFile)
                .where(StoredFile.owner_id == user.id)
                .order_by(StoredFile.created_at.desc())
            )
            results += [FileWithAccess(f, AccessLevel.OWNER) for f in owned]
        if scope in ("shared", "all") and has_permission(user.role, Permission.FILES_READ_SHARED):
            rows = await self.session.execute(
                select(StoredFile, FilePermission.level)
                .join(FilePermission, FilePermission.file_id == StoredFile.id)
                .where(
                    FilePermission.user_id == user.id,
                    or_(FilePermission.expires_at.is_(None), FilePermission.expires_at > utcnow()),
                )
                .order_by(StoredFile.created_at.desc())
            )
            results += [FileWithAccess(f, level) for f, level in rows]
        return results

    async def rename(self, user: User, file_id: uuid.UUID, filename: str) -> FileWithAccess:
        fa = await self.get_for(user, file_id, AccessLevel.EDITOR)
        old, fa.file.filename = fa.file.filename, sanitize_filename(filename)
        self.audit.record(
            AuditAction.FILE_RENAMED,
            actor_id=user.id,
            target_type="file",
            target_id=file_id,
            old=old,
            new=fa.file.filename,
        )
        await self.session.commit()
        return fa

    async def delete(self, user: User, file_id: uuid.UUID) -> None:
        fa = await self.get_for(user, file_id, AccessLevel.OWNER)
        key = fa.file.storage_key
        await self.session.delete(fa.file)
        self.audit.record(
            AuditAction.FILE_DELETED,
            actor_id=user.id,
            target_type="file",
            target_id=file_id,
            owner_id=str(fa.file.owner_id),
        )
        await self.session.commit()
        await self.storage.delete(key)
        log.info("file_deleted", file_id=str(file_id), by=str(user.id))

    def _clamp_ttl(self, ttl: int | None) -> int:
        ttl = ttl or self.settings.download_url_default_ttl_seconds
        return max(10, min(ttl, self.settings.download_url_max_ttl_seconds))

    async def download_url(
        self, user: User, file_id: uuid.UUID, ttl_seconds: int | None
    ) -> tuple[str, datetime]:
        fa = await self.get_for(user, file_id, AccessLevel.VIEWER)
        ttl = self._clamp_ttl(ttl_seconds)
        url = self.storage.presigned_download_url(
            fa.file.storage_key, filename=fa.file.filename, ttl_seconds=ttl
        )
        self.audit.record(
            AuditAction.FILE_DOWNLOAD_URL,
            actor_id=user.id,
            target_type="file",
            target_id=file_id,
            access=fa.access.value,
            ttl_seconds=ttl,
        )
        await self.session.commit()
        return url, utcnow() + timedelta(seconds=ttl)

    # --- per-user grants ----------------------------------------------------------------
    async def grant(
        self,
        owner: User,
        file_id: uuid.UUID,
        *,
        email: str,
        level: AccessLevel,
        expires_in_seconds: int | None,
    ) -> GrantWithEmail:
        if level == AccessLevel.OWNER:
            raise ValidationFailed("Ownership cannot be granted; use viewer or editor")
        if not has_permission(owner.role, Permission.FILES_SHARE):
            raise PermissionDenied("Your role cannot share files")
        fa = await self.get_for(owner, file_id, AccessLevel.OWNER)
        grantee = await self.session.scalar(
            select(User).where(User.email == normalize_email(email))
        )
        if grantee is None or not grantee.is_active:
            raise NotFound("No active user with that email")
        if grantee.id == fa.file.owner_id:
            raise Conflict("The owner already has full access")
        expires_at = (
            utcnow() + timedelta(seconds=expires_in_seconds) if expires_in_seconds else None
        )
        grant = await self.session.scalar(
            select(FilePermission).where(
                FilePermission.file_id == file_id, FilePermission.user_id == grantee.id
            )
        )
        if grant is None:
            grant = FilePermission(file_id=file_id, user_id=grantee.id)
            self.session.add(grant)
        grant.level = level
        grant.expires_at = expires_at
        grant.granted_by_id = owner.id
        self.audit.record(
            AuditAction.GRANT_CREATED,
            actor_id=owner.id,
            target_type="file",
            target_id=file_id,
            grantee_id=str(grantee.id),
            level=level.value,
            expires_at=expires_at.isoformat() if expires_at else None,
        )
        await self.session.commit()
        await self.session.refresh(grant)
        return GrantWithEmail(grant, grantee.email)

    async def list_grants(self, owner: User, file_id: uuid.UUID) -> list[GrantWithEmail]:
        await self.get_for(owner, file_id, AccessLevel.OWNER)
        rows = await self.session.execute(
            select(FilePermission, User.email)
            .join(User, User.id == FilePermission.user_id)
            .where(FilePermission.file_id == file_id)
            .order_by(FilePermission.created_at)
        )
        return [GrantWithEmail(g, e) for g, e in rows]

    async def revoke_grant(self, owner: User, file_id: uuid.UUID, user_id: uuid.UUID) -> None:
        await self.get_for(owner, file_id, AccessLevel.OWNER)
        grant = await self.session.scalar(
            select(FilePermission).where(
                FilePermission.file_id == file_id, FilePermission.user_id == user_id
            )
        )
        if grant is None:
            raise NotFound("No such grant")
        await self.session.delete(grant)
        self.audit.record(
            AuditAction.GRANT_REVOKED,
            actor_id=owner.id,
            target_type="file",
            target_id=file_id,
            grantee_id=str(user_id),
        )
        await self.session.commit()

    # --- anonymous share links ----------------------------------------------------------
    async def create_link(
        self,
        owner: User,
        file_id: uuid.UUID,
        *,
        expires_in_seconds: int,
        max_downloads: int | None,
    ) -> tuple[ShareLink, str]:
        if not has_permission(owner.role, Permission.FILES_SHARE):
            raise PermissionDenied("Your role cannot share files")
        await self.get_for(owner, file_id, AccessLevel.OWNER)
        if expires_in_seconds > self.settings.share_link_max_ttl_seconds:
            raise ValidationFailed(
                f"Share links can live at most {self.settings.share_link_max_ttl_seconds}s"
            )
        token = new_opaque_token()
        link = ShareLink(
            id=uuid.uuid4(),
            file_id=file_id,
            created_by_id=owner.id,
            token_hash=hash_opaque_token(token),
            expires_at=utcnow() + timedelta(seconds=expires_in_seconds),
            max_downloads=max_downloads,
            download_count=0,
        )
        self.session.add(link)
        self.audit.record(
            AuditAction.LINK_CREATED,
            actor_id=owner.id,
            target_type="share_link",
            target_id=link.id,
            file_id=str(file_id),
            expires_in_seconds=expires_in_seconds,
            max_downloads=max_downloads,
        )
        await self.session.commit()
        await self.session.refresh(link)
        return link, token

    async def list_links(self, owner: User, file_id: uuid.UUID) -> list[ShareLink]:
        await self.get_for(owner, file_id, AccessLevel.OWNER)
        rows = await self.session.scalars(
            select(ShareLink).where(ShareLink.file_id == file_id).order_by(ShareLink.created_at)
        )
        return list(rows)

    async def revoke_link(self, owner: User, file_id: uuid.UUID, link_id: uuid.UUID) -> None:
        await self.get_for(owner, file_id, AccessLevel.OWNER)
        link = await self.session.get(ShareLink, link_id)
        if link is None or link.file_id != file_id:
            raise NotFound("No such share link")
        if link.revoked_at is None:
            link.revoked_at = utcnow()
            self.audit.record(
                AuditAction.LINK_REVOKED,
                actor_id=owner.id,
                target_type="share_link",
                target_id=link_id,
                file_id=str(file_id),
            )
            await self.session.commit()

    async def redeem_link(self, token: str) -> str:
        """Count one download and return a short-lived presigned URL.

        The counter is bumped with a single conditional UPDATE, so concurrent requests
        can never push a capped link past ``max_downloads``.
        """
        now = utcnow()
        link_id = await self.session.scalar(
            update(ShareLink)
            .where(
                ShareLink.token_hash == hash_opaque_token(token),
                ShareLink.revoked_at.is_(None),
                ShareLink.expires_at > now,
                or_(
                    ShareLink.max_downloads.is_(None),
                    ShareLink.download_count < ShareLink.max_downloads,
                ),
            )
            .values(download_count=ShareLink.download_count + 1)
            .returning(ShareLink.id)
        )
        if link_id is None:
            await self.session.rollback()
            existing = await self.session.scalar(
                select(ShareLink.id).where(ShareLink.token_hash == hash_opaque_token(token))
            )
            await self.audit.record_now(
                AuditAction.LINK_REJECTED,
                outcome=Outcome.FAILURE,
                target_type="share_link" if existing else None,
                target_id=existing,
                reason="unknown_token" if existing is None else "expired_revoked_or_exhausted",
            )
            if existing is None:
                raise NotFound("Share link not found")
            raise Gone("This share link has expired, been revoked, or reached its download limit")
        file = await self.session.scalar(
            select(StoredFile)
            .join(ShareLink, ShareLink.file_id == StoredFile.id)
            .where(ShareLink.id == link_id)
        )
        if file is not None:
            self.audit.record(
                AuditAction.LINK_REDEEMED,
                target_type="share_link",
                target_id=link_id,
                file_id=str(file.id),
            )
        await self.session.commit()
        if file is None:  # pragma: no cover - FK cascade makes this unreachable
            raise NotFound("Share link not found")
        return self.storage.presigned_download_url(
            file.storage_key,
            filename=file.filename,
            ttl_seconds=self.settings.share_link_redirect_ttl_seconds,
        )
