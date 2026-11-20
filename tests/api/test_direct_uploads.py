"""Direct-to-S3 uploads: presigned POST, then a confirm step that trusts nothing."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select, update

from app.core.rbac import Role
from app.core.security import utcnow
from app.models import AuditEvent, StoredFile, UploadIntent
from app.resources import Resources
from tests.conftest import TestUser, UserFactory

DATA = b"large video bytes " * 500
SHA = hashlib.sha256(DATA).hexdigest()


async def start(client: httpx.AsyncClient, user: TestUser, **overrides: Any) -> httpx.Response:
    body = {
        "filename": "clip.mp4",
        "content_type": "video/mp4",
        "size_bytes": len(DATA),
        **overrides,
    }
    return await client.post("/files/uploads", headers=user.headers, json=body)


async def post_to_s3(
    started: dict[str, Any], data: bytes = DATA, **field_overrides: str
) -> httpx.Response:
    fields = {**started["fields"], **field_overrides}
    async with httpx.AsyncClient() as raw:
        return await raw.post(started["url"], data=fields, files={"file": ("blob", data)})


async def complete(client: httpx.AsyncClient, user: TestUser, upload_id: str) -> httpx.Response:
    return await client.post(f"/files/uploads/{upload_id}/complete", headers=user.headers)


async def object_exists(resources: Resources, upload_id: str, owner: TestUser) -> bool:
    return await resources.storage.head(f"files/{owner.id}/{upload_id}") is not None


def policy(started: dict[str, Any]) -> dict[str, Any]:
    decoded: dict[str, Any] = json.loads(base64.b64decode(started["fields"]["policy"]))
    return decoded


async def test_direct_upload_round_trip(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner = await make_user()
    r = await start(client, owner)
    assert r.status_code == 201, r.text
    started = r.json()
    assert started["complete_url"].endswith(f"/files/uploads/{started['upload_id']}/complete")
    assert (await post_to_s3(started)).status_code in (200, 201, 204)

    done = await complete(client, owner, started["upload_id"])
    assert done.status_code == 201, done.text
    file = done.json()
    assert file["id"] == started["upload_id"]
    assert (file["size_bytes"], file["sha256"]) == (len(DATA), SHA)
    assert (file["filename"], file["content_type"], file["access"]) == (
        "clip.mp4",
        "video/mp4",
        "owner",
    )
    # It is now an ordinary file: listed and downloadable.
    listed = await client.get("/files", headers=owner.headers)
    assert [f["id"] for f in listed.json()] == [file["id"]]
    url = (await client.get(f"/files/{file['id']}/download", headers=owner.headers)).json()["url"]
    async with httpx.AsyncClient() as raw:
        assert (await raw.get(url)).content == DATA
    async with resources.sessionmaker() as s:
        assert await s.scalar(select(UploadIntent)) is None
        event = await s.scalar(select(AuditEvent).where(AuditEvent.action == "file.uploaded"))
    assert event is not None
    assert event.details["method"] == "direct"


async def test_policy_pins_key_size_type_and_checksum(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner = await make_user()
    started = (await start(client, owner, sha256=SHA.upper())).json()
    conditions = policy(started)["conditions"]
    checksum = base64.b64encode(bytes.fromhex(SHA)).decode()
    assert {"key": f"files/{owner.id}/{started['upload_id']}"} in conditions
    assert ["content-length-range", len(DATA), len(DATA)] in conditions
    assert {"Content-Type": "video/mp4"} in conditions
    assert {"x-amz-checksum-sha256": checksum} in conditions
    assert started["fields"]["x-amz-checksum-sha256"] == checksum


async def test_declared_checksum_is_verified(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner = await make_user()
    started = (await start(client, owner, sha256=SHA)).json()
    await post_to_s3(started)
    r = await complete(client, owner, started["upload_id"])
    assert r.status_code == 201
    assert r.json()["sha256"] == SHA


@pytest.mark.parametrize(
    ("tamper", "reason"),
    [
        ({"data": DATA[:-1] + b"X", "sha256": SHA}, "checksum_mismatch"),
        ({"data": DATA + b"extra"}, "size_mismatch"),
        ({"fields": {"Content-Type": "text/html"}}, "content_type_mismatch"),
    ],
)
async def test_mismatching_objects_are_rejected_and_deleted(
    client: httpx.AsyncClient,
    make_user: UserFactory,
    resources: Resources,
    tamper: dict[str, Any],
    reason: str,
) -> None:
    """Real S3 enforces the POST policy; the confirm step re-checks anyway."""
    owner = await make_user()
    overrides = {"sha256": tamper["sha256"]} if "sha256" in tamper else {}
    started = (await start(client, owner, **overrides)).json()
    await post_to_s3(started, tamper.get("data", DATA), **tamper.get("fields", {}))
    assert await object_exists(resources, started["upload_id"], owner)

    r = await complete(client, owner, started["upload_id"])
    assert r.status_code == 422, r.text
    assert not await object_exists(resources, started["upload_id"], owner)
    # The intent is gone too: retrying cannot resurrect it.
    assert (await complete(client, owner, started["upload_id"])).status_code == 404
    async with resources.sessionmaker() as s:
        assert await s.scalar(select(StoredFile)) is None
        event = await s.scalar(
            select(AuditEvent).where(AuditEvent.action == "file.upload_rejected")
        )
    assert event is not None
    assert event.details == {"reason": reason}


async def test_completing_before_the_upload_keeps_the_intent(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner = await make_user()
    started = (await start(client, owner)).json()
    early = await complete(client, owner, started["upload_id"])
    assert early.status_code == 422
    assert "No object" in early.json()["error"]["message"]
    await post_to_s3(started)
    assert (await complete(client, owner, started["upload_id"])).status_code == 201


async def test_expired_intent_is_gone_and_cleaned_up(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner = await make_user()
    started = (await start(client, owner)).json()
    await post_to_s3(started)
    async with resources.sessionmaker() as s:
        await s.execute(update(UploadIntent).values(expires_at=utcnow() - timedelta(hours=1)))
        await s.commit()
    r = await complete(client, owner, started["upload_id"])
    assert r.status_code == 410
    assert not await object_exists(resources, started["upload_id"], owner)


async def test_only_the_uploader_can_complete(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner = await make_user()
    other = await make_user()
    started = (await start(client, owner)).json()
    await post_to_s3(started)
    assert (await complete(client, other, started["upload_id"])).status_code == 404
    assert (await complete(client, owner, started["upload_id"])).status_code == 201
    # Completing twice does not create a second file.
    assert (await complete(client, owner, started["upload_id"])).status_code == 404


async def test_direct_upload_permissions_and_validation(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    guest = await make_user(role=Role.GUEST)
    assert (await start(client, guest)).status_code == 403
    member = await make_user()
    too_big = resources.settings.direct_upload_max_bytes + 1
    assert (await start(client, member, size_bytes=too_big)).status_code == 413
    assert (await start(client, member, size_bytes=0)).status_code == 422
    assert (await start(client, member, sha256="not-a-hash")).status_code == 422
    assert (await client.post("/files/uploads", json={})).status_code == 401


async def test_filename_and_content_type_are_sanitised(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner = await make_user()
    started = (
        await start(client, owner, filename="../../etc/passwd", content_type="bogus type")
    ).json()
    assert {"Content-Type": "application/octet-stream"} in policy(started)["conditions"]
    await post_to_s3(started)
    file = (await complete(client, owner, started["upload_id"])).json()
    assert (file["filename"], file["content_type"]) == ("passwd", "application/octet-stream")
