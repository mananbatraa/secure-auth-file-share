from __future__ import annotations

import hashlib
import io
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from botocore.exceptions import ClientError
from sqlalchemy import update

from app.core.rbac import Role
from app.core.security import utcnow
from app.models import FilePermission
from app.resources import Resources
from tests.conftest import TestUser, UserFactory

CONTENT = b"quarterly numbers\n" * 100


async def upload(
    client: httpx.AsyncClient,
    user: TestUser,
    content: bytes = CONTENT,
    name: str = "report.txt",
    ctype: str = "text/plain",
) -> httpx.Response:
    return await client.post(
        "/files", headers=user.headers, files={"upload": (name, io.BytesIO(content), ctype)}
    )


async def share(
    client: httpx.AsyncClient,
    owner: TestUser,
    file_id: str,
    email: str,
    level: str = "viewer",
    **kw: object,
) -> httpx.Response:
    return await client.post(
        f"/files/{file_id}/permissions",
        headers=owner.headers,
        json={"email": email, "level": level, **kw},
    )


async def test_upload_stores_metadata_and_object(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner = await make_user()
    r = await upload(client, owner)
    assert r.status_code == 201
    body = r.json()
    assert body["filename"] == "report.txt"
    assert body["size_bytes"] == len(CONTENT)
    assert body["sha256"] == hashlib.sha256(CONTENT).hexdigest()
    assert body["access"] == "owner"
    assert body["content_type"] == "text/plain"


async def test_download_url_serves_the_bytes_as_attachment(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner = await make_user()
    file_id = (await upload(client, owner, name="résumé.html", ctype="text/html")).json()["id"]
    r = await client.get(f"/files/{file_id}/download", headers=owner.headers, params={"ttl": 120})
    assert r.status_code == 200
    url = r.json()["url"]
    assert parse_qs(urlparse(url).query)["X-Amz-Expires"] == ["120"]
    async with httpx.AsyncClient() as raw:
        obj = await raw.get(url)
    assert obj.status_code == 200
    assert obj.content == CONTENT
    # Uploaded HTML is forced to download, never rendered.
    assert obj.headers["content-disposition"].startswith("attachment;")


async def test_download_ttl_is_clamped(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner = await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    r = await client.get(
        f"/files/{file_id}/download", headers=owner.headers, params={"ttl": 999_999}
    )
    url = r.json()["url"]
    expected = str(resources.settings.download_url_max_ttl_seconds)
    assert parse_qs(urlparse(url).query)["X-Amz-Expires"] == [expected]


async def test_strangers_get_404_not_403(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    owner, stranger = await make_user(), await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    for method, path in [
        ("GET", f"/files/{file_id}"),
        ("GET", f"/files/{file_id}/download"),
        ("DELETE", f"/files/{file_id}"),
        ("GET", f"/files/{file_id}/permissions"),
        ("GET", f"/files/{file_id}/links"),
    ]:
        r = await client.request(method, path, headers=stranger.headers)
        assert r.status_code == 404, (method, path)


async def test_viewer_can_read_but_not_modify(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner, viewer = await make_user(), await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    g = await share(client, owner, file_id, viewer.email)
    assert g.status_code == 201
    assert g.json()["email"] == viewer.email

    r = await client.get(f"/files/{file_id}", headers=viewer.headers)
    assert r.status_code == 200
    assert r.json()["access"] == "viewer"
    assert (
        await client.get(f"/files/{file_id}/download", headers=viewer.headers)
    ).status_code == 200
    rename = await client.patch(f"/files/{file_id}", headers=viewer.headers, json={"filename": "x"})
    assert rename.status_code == 403
    assert (await client.delete(f"/files/{file_id}", headers=viewer.headers)).status_code == 403
    reshare = await share(client, viewer, file_id, owner.email)
    assert reshare.status_code == 403


async def test_editor_can_rename_but_not_delete_or_share(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner, editor, third = await make_user(), await make_user(), await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    await share(client, owner, file_id, editor.email, level="editor")
    r = await client.patch(
        f"/files/{file_id}", headers=editor.headers, json={"filename": "../q3.txt"}
    )
    assert r.status_code == 200
    assert r.json()["filename"] == "q3.txt"
    assert (await client.delete(f"/files/{file_id}", headers=editor.headers)).status_code == 403
    assert (await share(client, editor, file_id, third.email)).status_code == 403


async def test_regranting_updates_level(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    owner, other = await make_user(), await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    await share(client, owner, file_id, other.email, level="viewer")
    await share(client, owner, file_id, other.email, level="editor")
    grants = (await client.get(f"/files/{file_id}/permissions", headers=owner.headers)).json()
    assert len(grants) == 1
    assert grants[0]["level"] == "editor"


async def test_grant_validation(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    owner = await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    assert (await share(client, owner, file_id, "ghost@example.com")).status_code == 404
    assert (await share(client, owner, file_id, owner.email)).status_code == 409
    other = await make_user()
    assert (await share(client, owner, file_id, other.email, level="owner")).status_code == 422


async def test_expired_grant_hides_file(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner, viewer = await make_user(), await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    r = await share(client, owner, file_id, viewer.email, expires_in_seconds=3600)
    assert r.json()["expires_at"] is not None
    assert (await client.get(f"/files/{file_id}", headers=viewer.headers)).status_code == 200
    async with resources.sessionmaker() as s:
        await s.execute(update(FilePermission).values(expires_at=utcnow() - timedelta(seconds=1)))
        await s.commit()
    assert (await client.get(f"/files/{file_id}", headers=viewer.headers)).status_code == 404
    listed = (await client.get("/files", headers=viewer.headers, params={"scope": "shared"})).json()
    assert listed == []


async def test_revoke_grant(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    owner, viewer = await make_user(), await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    grant = (await share(client, owner, file_id, viewer.email)).json()
    r = await client.delete(
        f"/files/{file_id}/permissions/{grant['user_id']}", headers=owner.headers
    )
    assert r.status_code == 204
    assert (await client.get(f"/files/{file_id}", headers=viewer.headers)).status_code == 404
    r = await client.delete(
        f"/files/{file_id}/permissions/{grant['user_id']}", headers=owner.headers
    )
    assert r.status_code == 404


async def test_list_scopes(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    alice, bob = await make_user(), await make_user()
    mine = (await upload(client, alice, name="mine.txt")).json()["id"]
    theirs = (await upload(client, bob, name="theirs.txt")).json()["id"]
    await share(client, bob, theirs, alice.email)

    async def ids(scope: str) -> set[str]:
        r = await client.get("/files", headers=alice.headers, params={"scope": scope})
        return {f["id"] for f in r.json()}

    assert await ids("owned") == {mine}
    assert await ids("shared") == {theirs}
    assert await ids("all") == {mine, theirs}


async def test_owner_delete_removes_object(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner = await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    url = (await client.get(f"/files/{file_id}/download", headers=owner.headers)).json()["url"]
    key = urlparse(url).path.split("/", 2)[2]  # path-style: /<bucket>/<key>
    s3 = resources.storage._client
    s3.head_object(Bucket=resources.storage.bucket, Key=key)
    assert (await client.delete(f"/files/{file_id}", headers=owner.headers)).status_code == 204
    assert (await client.get(f"/files/{file_id}", headers=owner.headers)).status_code == 404
    with pytest.raises(ClientError) as exc:
        s3.head_object(Bucket=resources.storage.bucket, Key=key)
    assert exc.value.response["Error"]["Code"] == "404"


async def test_admin_can_manage_any_file(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    owner = await make_user()
    admin = await make_user("admin@example.com", role=Role.ADMIN)
    file_id = (await upload(client, owner)).json()["id"]
    assert (await client.get(f"/files/{file_id}", headers=admin.headers)).status_code == 200
    assert (await client.delete(f"/files/{file_id}", headers=admin.headers)).status_code == 204


async def test_guest_can_read_shared_files_but_not_upload(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner = await make_user()
    guest = await make_user("guest@example.com", role=Role.GUEST)
    file_id = (await upload(client, owner)).json()["id"]
    await share(client, owner, file_id, guest.email)
    assert (
        await client.get(f"/files/{file_id}/download", headers=guest.headers)
    ).status_code == 200
    assert (await upload(client, guest)).status_code == 403


async def test_upload_limits(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner = await make_user()
    too_big = b"x" * (resources.settings.max_upload_bytes + 1)
    r = await upload(client, owner, content=too_big)
    assert r.status_code == 413
    assert (await upload(client, owner, content=b"")).status_code == 422
    assert (await client.get("/files", headers=owner.headers)).json() == []


async def test_upload_sanitises_name_and_type(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner = await make_user()
    r = await upload(client, owner, name="../../etc/passwd", ctype="bogus")
    assert r.json()["filename"] == "passwd"
    assert r.json()["content_type"] == "application/octet-stream"


async def test_requires_authentication(client: httpx.AsyncClient) -> None:
    r = await client.post("/files", files={"upload": ("a.txt", io.BytesIO(b"x"), "text/plain")})
    assert r.status_code == 401
