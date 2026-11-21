from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class AccessLevel(StrEnum):
    VIEWER = "viewer"
    EDITOR = "editor"
    OWNER = "owner"  # never stored on a grant; the owner is files.owner_id

    @property
    def rank(self) -> int:
        return {"viewer": 1, "editor": 2, "owner": 3}[self.value]


class StoredFile(TimestampMixin, Base):
    __tablename__ = "files"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    # Server-generated; never derived from user input.
    storage_key: Mapped[str] = mapped_column(String(512), unique=True)


class FilePermission(TimestampMixin, Base):
    """A per-user grant on one file."""

    __tablename__ = "file_permissions"
    __table_args__ = (UniqueConstraint("file_id", "user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    level: Mapped[AccessLevel] = mapped_column(
        Enum(AccessLevel, name="access_level", values_callable=lambda e: [m.value for m in e])
    )
    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class ShareLink(TimestampMixin, Base):
    """An anonymous, expiring, optionally download-capped link to one file."""

    __tablename__ = "share_links"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), index=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    max_downloads: Mapped[int | None] = mapped_column(Integer)
    download_count: Mapped[int] = mapped_column(Integer, default=0)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UploadIntent(TimestampMixin, Base):
    """A pending direct-to-S3 upload: the client POSTs to S3, then confirms with the API."""

    __tablename__ = "upload_intents"

    # Becomes the file's id on completion.
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    storage_key: Mapped[str] = mapped_column(String(512), unique=True)
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    # Client-declared SHA-256 (hex); verified before the file is accepted.
    sha256: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
