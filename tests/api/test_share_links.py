from __future__ import annotations

import asyncio
from datetime import timedelta

import httpx
from sqlalchemy import update

from app.core.security import utcnow
from app.models import ShareLink
from app.resources import Resources
from tests.api.test_files import CONTENT, upload
from tests.conftest import TestUser, UserFactory


async def make_link(
    client: httpx.AsyncClient, owner: TestUser, file_id: str, **body: object
) -> httpx.Response:
    return await client.post(f"/files/{file_id}/links", headers=owner.headers, json=body)


async def _setup(
    client: httpx.AsyncClient, make_user: UserFactory, **body: object
) -> tuple[TestUser, str, dict[str, object]]:
    owner = await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    r = await make_link(client, owner, file_id, **body)
    assert r.status_code == 201, r.text
    return owner, file_id, r.json()


async def test_link_redirects_to_working_presigned_url(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    _, _, link = await _setup(client, make_user, expires_in_seconds=3600)
    assert str(link["url"]).startswith("http://testserver/s/")
    r = await client.get(f"/s/{link['token']}")  # anonymous
    assert r.status_code == 307
    assert r.headers["cache-control"] == "no-store"
    async with httpx.AsyncClient() as raw:
        obj = await raw.get(r.headers["location"])
    assert obj.status_code == 200
    assert obj.content == CONTENT


async def test_token_is_shown_once_and_stored_hashed(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner, file_id, link = await _setup(client, make_user)
    listed = (await client.get(f"/files/{file_id}/links", headers=owner.headers)).json()
    assert len(listed) == 1
    assert "token" not in listed[0]
    assert "url" not in listed[0]
    assert listed[0]["id"] == link["id"]


async def test_max_downloads_is_enforced(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    owner, file_id, link = await _setup(client, make_user, max_downloads=2)
    assert (await client.get(f"/s/{link['token']}")).status_code == 307
    assert (await client.get(f"/s/{link['token']}")).status_code == 307
    r = await client.get(f"/s/{link['token']}")
    assert r.status_code == 410
    listed = (await client.get(f"/files/{file_id}/links", headers=owner.headers)).json()
    assert listed[0]["download_count"] == 2


async def test_concurrent_redemptions_respect_cap(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    _, _, link = await _setup(client, make_user, max_downloads=3)
    responses = await asyncio.gather(*(client.get(f"/s/{link['token']}") for _ in range(12)))
    codes = [r.status_code for r in responses]
    assert codes.count(307) == 3
    assert codes.count(410) == 9


async def test_expired_link_is_gone(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    _, _, link = await _setup(client, make_user)
    async with resources.sessionmaker() as s:
        await s.execute(update(ShareLink).values(expires_at=utcnow() - timedelta(seconds=1)))
        await s.commit()
    assert (await client.get(f"/s/{link['token']}")).status_code == 410


async def test_revoked_link_is_gone(client: httpx.AsyncClient, make_user: UserFactory) -> None:
    owner, file_id, link = await _setup(client, make_user)
    r = await client.delete(f"/files/{file_id}/links/{link['id']}", headers=owner.headers)
    assert r.status_code == 204
    assert (await client.get(f"/s/{link['token']}")).status_code == 410
    listed = (await client.get(f"/files/{file_id}/links", headers=owner.headers)).json()
    assert listed[0]["revoked_at"] is not None


async def test_unknown_link_is_404(client: httpx.AsyncClient) -> None:
    r = await client.get("/s/definitely-not-a-real-token")
    assert r.status_code == 404


async def test_deleting_file_kills_its_links(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner, file_id, link = await _setup(client, make_user)
    await client.delete(f"/files/{file_id}", headers=owner.headers)
    assert (await client.get(f"/s/{link['token']}")).status_code == 404


async def test_link_ttl_cannot_exceed_max(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner = await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    too_long = resources.settings.share_link_max_ttl_seconds + 1
    r = await make_link(client, owner, file_id, expires_in_seconds=too_long)
    assert r.status_code == 422


async def test_only_owner_can_create_links(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner, editor = await make_user(), await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    await client.post(
        f"/files/{file_id}/permissions",
        headers=owner.headers,
        json={"email": editor.email, "level": "editor"},
    )
    assert (await make_link(client, editor, file_id)).status_code == 403


async def test_redeeming_is_rate_limited_per_ip(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    limit = resources.settings.share_link_max_hits_per_ip
    for _ in range(limit):
        assert (await client.get("/s/guess")).status_code == 404
    r = await client.get("/s/guess")
    assert r.status_code == 429
    assert "retry-after" in r.headers


async def test_revoke_unknown_link_is_404(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    owner, file_id, _ = await _setup(client, make_user)
    r = await client.delete(
        f"/files/{file_id}/links/00000000-0000-0000-0000-000000000000", headers=owner.headers
    )
    assert r.status_code == 404
