from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from sqlalchemy import func, select

from app.models import OAuthAccount, User
from app.resources import Resources
from tests.conftest import UserFactory

GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


async def _start(client: httpx.AsyncClient, provider: str) -> dict[str, list[str]]:
    r = await client.get(f"/auth/oauth/{provider}/authorize")
    assert r.status_code == 302
    return parse_qs(urlparse(r.headers["location"]).query)


def mock_github(
    router: respx.MockRouter,
    *,
    account_id: int = 42,
    emails: list[dict[str, object]] | None = None,
) -> respx.Route:
    token = router.post(GITHUB_TOKEN_URL).respond(json={"access_token": "gh-access"})
    router.get("https://api.github.com/user").respond(json={"id": account_id, "login": "octo"})
    router.get("https://api.github.com/user/emails").respond(
        json=emails
        if emails is not None
        else [
            {"email": "old@example.com", "primary": False, "verified": True},
            {"email": "Octo@Example.com", "primary": True, "verified": True},
        ]
    )
    return token


async def test_authorize_redirects_with_state_and_pkce(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    q = await _start(client, "github")
    assert q["client_id"] == ["gh-client"]
    assert q["redirect_uri"] == ["http://testserver/auth/oauth/github/callback"]
    assert q["code_challenge_method"] == ["S256"]
    assert len(q["state"][0]) >= 32
    assert await resources.redis.exists(f"oauth:state:{q['state'][0]}")


async def test_github_login_creates_user(client: httpx.AsyncClient, resources: Resources) -> None:
    q = await _start(client, "github")
    with respx.mock(assert_all_called=True) as router:
        token_route = mock_github(router)
        r = await client.get(
            "/auth/oauth/github/callback", params={"code": "abc", "state": q["state"][0]}
        )
    assert r.status_code == 200, r.text
    sent = parse_qs(token_route.calls.last.request.content.decode())
    assert sent["code_verifier"][0]  # PKCE verifier sent back
    me = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"}
    )
    assert me.json()["email"] == "octo@example.com"
    async with resources.sessionmaker() as s:
        user = await s.scalar(select(User).where(User.email == "octo@example.com"))
        assert user is not None
        assert user.hashed_password is None


async def test_second_login_reuses_linked_account(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    for _ in range(2):
        q = await _start(client, "github")
        with respx.mock as router:
            mock_github(router)
            r = await client.get(
                "/auth/oauth/github/callback", params={"code": "abc", "state": q["state"][0]}
            )
        assert r.status_code == 200
    async with resources.sessionmaker() as s:
        assert await s.scalar(select(func.count()).select_from(User)) == 1
        assert await s.scalar(select(func.count()).select_from(OAuthAccount)) == 1


async def test_links_existing_password_account_by_verified_email(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    existing = await make_user("octo@example.com")
    q = await _start(client, "github")
    with respx.mock as router:
        mock_github(router)
        r = await client.get(
            "/auth/oauth/github/callback", params={"code": "abc", "state": q["state"][0]}
        )
    me = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"}
    )
    existing_me = await client.get("/users/me", headers=existing.headers)
    assert me.json()["id"] == existing_me.json()["id"]


async def test_github_without_verified_email_is_rejected(client: httpx.AsyncClient) -> None:
    q = await _start(client, "github")
    with respx.mock as router:
        mock_github(router, emails=[{"email": "x@example.com", "primary": True, "verified": False}])
        r = await client.get(
            "/auth/oauth/github/callback", params={"code": "abc", "state": q["state"][0]}
        )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "oauth_error"


async def test_google_unverified_email_cannot_take_over_account(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    await make_user("victim@example.com")
    q = await _start(client, "google")
    assert q["prompt"] == ["select_account"]
    with respx.mock as router:
        router.post(GOOGLE_TOKEN_URL).respond(json={"access_token": "g"})
        router.get("https://openidconnect.googleapis.com/v1/userinfo").respond(
            json={"sub": "g-1", "email": "victim@example.com", "email_verified": False}
        )
        r = await client.get(
            "/auth/oauth/google/callback", params={"code": "abc", "state": q["state"][0]}
        )
    assert r.status_code == 400


async def test_google_login(client: httpx.AsyncClient) -> None:
    q = await _start(client, "google")
    with respx.mock as router:
        router.post(GOOGLE_TOKEN_URL).respond(json={"access_token": "g"})
        router.get("https://openidconnect.googleapis.com/v1/userinfo").respond(
            json={"sub": "g-1", "email": "g@example.com", "email_verified": True}
        )
        r = await client.get(
            "/auth/oauth/google/callback", params={"code": "abc", "state": q["state"][0]}
        )
    assert r.status_code == 200


async def test_state_is_single_use_and_provider_bound(client: httpx.AsyncClient) -> None:
    q = await _start(client, "github")
    state = q["state"][0]
    # Presenting a GitHub state to the Google callback fails and burns it.
    r = await client.get("/auth/oauth/google/callback", params={"code": "abc", "state": state})
    assert r.status_code == 400
    with respx.mock as router:
        mock_github(router)
        r = await client.get("/auth/oauth/github/callback", params={"code": "abc", "state": state})
    assert r.status_code == 400


async def test_replayed_state_is_rejected(client: httpx.AsyncClient) -> None:
    q = await _start(client, "github")
    params = {"code": "abc", "state": q["state"][0]}
    with respx.mock as router:
        mock_github(router)
        assert (await client.get("/auth/oauth/github/callback", params=params)).status_code == 200
        assert (await client.get("/auth/oauth/github/callback", params=params)).status_code == 400


async def test_unknown_state_is_rejected(client: httpx.AsyncClient) -> None:
    r = await client.get("/auth/oauth/github/callback", params={"code": "a", "state": "forged"})
    assert r.status_code == 400


@pytest.mark.parametrize("status", [401, 500])
async def test_provider_errors_become_400(client: httpx.AsyncClient, status: int) -> None:
    q = await _start(client, "github")
    with respx.mock as router:
        router.post(GITHUB_TOKEN_URL).respond(status_code=status)
        r = await client.get(
            "/auth/oauth/github/callback", params={"code": "abc", "state": q["state"][0]}
        )
    assert r.status_code == 400


async def test_token_response_without_access_token(client: httpx.AsyncClient) -> None:
    q = await _start(client, "github")
    with respx.mock as router:
        router.post(GITHUB_TOKEN_URL).respond(json={"error": "bad_verification_code"})
        r = await client.get(
            "/auth/oauth/github/callback", params={"code": "abc", "state": q["state"][0]}
        )
    assert r.status_code == 400


async def test_unknown_or_unconfigured_provider_is_404(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    assert (await client.get("/auth/oauth/myspace/authorize")).status_code == 404
    resources.settings = resources.settings.model_copy(update={"google_client_id": None})
    assert (await client.get("/auth/oauth/google/authorize")).status_code == 404


async def test_disabled_linked_account_cannot_login(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    q = await _start(client, "github")
    with respx.mock as router:
        mock_github(router)
        await client.get(
            "/auth/oauth/github/callback", params={"code": "a", "state": q["state"][0]}
        )
    async with resources.sessionmaker() as s:
        user = await s.scalar(select(User))
        assert user is not None
        user.is_active = False
        await s.commit()
    q = await _start(client, "github")
    with respx.mock as router:
        mock_github(router)
        r = await client.get(
            "/auth/oauth/github/callback", params={"code": "a", "state": q["state"][0]}
        )
    assert r.status_code == 403
