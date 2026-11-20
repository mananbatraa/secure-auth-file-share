"""S3-compatible object storage (AWS S3 or MinIO)."""

from __future__ import annotations

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
