from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.file import AccessLevel


class FileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime
    access: AccessLevel


class FileRename(BaseModel):
    filename: str = Field(min_length=1, max_length=255)


class DownloadUrl(BaseModel):
    url: str
    expires_at: datetime


class GrantRequest(BaseModel):
    email: EmailStr
    level: AccessLevel = AccessLevel.VIEWER
    expires_in_seconds: int | None = Field(default=None, ge=60)


class GrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    file_id: uuid.UUID
    user_id: uuid.UUID
    email: EmailStr
    level: AccessLevel
    expires_at: datetime | None
    created_at: datetime


class ShareLinkCreate(BaseModel):
    expires_in_seconds: int = Field(default=24 * 3600, ge=60)
    max_downloads: int | None = Field(default=None, ge=1, le=10_000)


class ShareLinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    file_id: uuid.UUID
    expires_at: datetime
    max_downloads: int | None
    download_count: int
    revoked_at: datetime | None
    created_at: datetime


class ShareLinkCreated(ShareLinkOut):
    # The raw token is only ever returned here; the server stores its hash.
    token: str
    url: str
