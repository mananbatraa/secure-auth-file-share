"""S3-compatible object storage (AWS S3 or MinIO)."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING, Any
from urllib.parse import quote

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from starlette.concurrency import run_in_threadpool

from app.core.config import Settings

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client


def _client(settings: Settings, endpoint_url: str | None) -> S3Client:
    secret = settings.s3_secret_access_key
    return boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        region_name=settings.s3_region,
        aws_access_key_id=settings.s3_access_key_id,
        aws_secret_access_key=secret.get_secret_value() if secret else None,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def content_disposition(filename: str) -> str:
    """Always ``attachment`` so stored HTML/SVG can never render on our origin."""
    ascii_name = filename.encode("ascii", "ignore").decode()
    ascii_name = "".join(ch for ch in ascii_name if ch.isprintable() and ch not in '"\\')
    if not any(ch.isalnum() for ch in ascii_name):
        ascii_name = "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"


@dataclass(frozen=True, slots=True)
class ObjectInfo:
    size_bytes: int
    content_type: str | None
    # Hex SHA-256 when S3 stored a full-object checksum for this object, else None.
    sha256: str | None


@dataclass(frozen=True, slots=True)
class PresignedPost:
    url: str
    fields: dict[str, str]


class ObjectStorage:
    def __init__(self, settings: Settings) -> None:
        self.bucket = settings.s3_bucket
        self._client = _client(settings, settings.s3_endpoint_url)
        # Presigned URLs embed the host in the signature, so sign with the host the
        # *browser* will use.
        public = settings.s3_public_endpoint_url or settings.s3_endpoint_url
        self._signer = (
            self._client if public == settings.s3_endpoint_url else _client(settings, public)
        )

    async def ensure_bucket(self) -> None:
        def _ensure() -> None:
            try:
                self._client.head_bucket(Bucket=self.bucket)
            except ClientError:
                self._client.create_bucket(Bucket=self.bucket)

        await run_in_threadpool(_ensure)

    async def ping(self) -> None:
        await run_in_threadpool(self._client.head_bucket, Bucket=self.bucket)

    async def upload(self, key: str, fileobj: IO[bytes], *, content_type: str) -> None:
        extra: dict[str, Any] = {"ContentType": content_type}
        await run_in_threadpool(
            self._client.upload_fileobj, fileobj, self.bucket, key, ExtraArgs=extra
        )

    async def delete(self, key: str) -> None:
        await run_in_threadpool(self._client.delete_object, Bucket=self.bucket, Key=key)

    def presigned_download_url(self, key: str, *, filename: str, ttl_seconds: int) -> str:
        return self._signer.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.bucket,
                "Key": key,
                "ResponseContentDisposition": content_disposition(filename),
            },
            ExpiresIn=ttl_seconds,
        )

    def presigned_upload(
        self,
        key: str,
        *,
        content_type: str,
        size_bytes: int,
        sha256: str | None,
        ttl_seconds: int,
    ) -> PresignedPost:
        """A browser-usable POST policy pinned to one key, exact size and content type.

        With a declared SHA-256, S3 also verifies the body against it on upload.
        """
        fields: dict[str, Any] = {"Content-Type": content_type}
        conditions: list[Any] = [
            {"Content-Type": content_type},
            ["content-length-range", size_bytes, size_bytes],
        ]
        if sha256:
            checksum = base64.b64encode(bytes.fromhex(sha256)).decode()
            fields["x-amz-checksum-sha256"] = checksum
            conditions.append({"x-amz-checksum-sha256": checksum})
        post = self._signer.generate_presigned_post(
            self.bucket, key, Fields=fields, Conditions=conditions, ExpiresIn=ttl_seconds
        )
        return PresignedPost(url=post["url"], fields={k: str(v) for k, v in post["fields"].items()})

    async def head(self, key: str) -> ObjectInfo | None:
        def _head() -> ObjectInfo | None:
            try:
                meta = self._client.head_object(Bucket=self.bucket, Key=key, ChecksumMode="ENABLED")
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                    return None
                raise
            checksum = meta.get("ChecksumSHA256")
            # Multipart checksums ("<b64>-<parts>") are checksums of checksums: not usable.
            sha = base64.b64decode(checksum).hex() if checksum and "-" not in checksum else None
            return ObjectInfo(meta["ContentLength"], meta.get("ContentType"), sha)

        return await run_in_threadpool(_head)

    async def sha256(self, key: str) -> str:
        """Hash an object by streaming it (fallback when S3 has no stored checksum)."""

        def _hash() -> str:
            body = self._client.get_object(Bucket=self.bucket, Key=key)["Body"]
            digest = hashlib.sha256()
            for chunk in body.iter_chunks(1024 * 1024):
                digest.update(chunk)
            return digest.hexdigest()

        return await run_in_threadpool(_hash)
