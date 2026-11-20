"""ObjectStorage.head: the S3-checksum fast path that moto does not exercise."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest
from botocore.exceptions import ClientError

from app.core.config import Settings
from app.services.storage import ObjectStorage

DIGEST = hashlib.sha256(b"payload").digest()


class StubClient:
    def __init__(self, response: dict[str, Any] | None = None, error: str | None = None) -> None:
        self.response = response or {}
        self.error = error
        self.kwargs: dict[str, Any] = {}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.kwargs = kwargs
        if self.error:
            raise ClientError({"Error": {"Code": self.error}}, "HeadObject")
        return self.response


def storage_with(stub: StubClient) -> ObjectStorage:
    store = ObjectStorage(Settings(s3_endpoint_url="http://127.0.0.1:1", s3_bucket="unit-test"))
    store._client = stub  # type: ignore[assignment]
    return store


async def test_full_object_checksum_is_used() -> None:
    stub = StubClient(
        {
            "ContentLength": 7,
            "ContentType": "text/plain",
            "ChecksumSHA256": base64.b64encode(DIGEST).decode(),
        }
    )
    info = await storage_with(stub).head("k")
    assert info is not None
    assert (info.size_bytes, info.content_type, info.sha256) == (7, "text/plain", DIGEST.hex())
    assert stub.kwargs == {"Bucket": "unit-test", "Key": "k", "ChecksumMode": "ENABLED"}


async def test_multipart_checksum_is_ignored() -> None:
    checksum = base64.b64encode(DIGEST).decode() + "-3"
    info = await storage_with(StubClient({"ContentLength": 7, "ChecksumSHA256": checksum})).head(
        "k"
    )
    assert info is not None
    assert info.sha256 is None
    assert info.content_type is None


@pytest.mark.parametrize("code", ["404", "NoSuchKey", "NotFound"])
async def test_missing_object_is_none(code: str) -> None:
    assert await storage_with(StubClient(error=code)).head("k") is None


async def test_other_errors_propagate() -> None:
    with pytest.raises(ClientError):
        await storage_with(StubClient(error="AccessDenied")).head("k")
