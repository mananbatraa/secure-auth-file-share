"""Browser sessions: refresh token in an HttpOnly cookie, CSRF on refresh and logout."""

from __future__ import annotations

from collections.abc import AsyncIterator
from http.cookies import SimpleCookie

import httpx
import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.security import csrf_token_for
from app.main import create_app
from app.resources import Resources
from tests.conftest import PASSWORD, UserFactory

COOKIE_MODE = {"X-Token-Delivery": "cookie"}


@pytest.fixture
async def browser(resources: Resources) -> AsyncIterator[httpx.AsyncClient]:
    """A client on https, so the cookie jar keeps and sends Secure cookies."""
    app = create_app(resources=resources)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
        yield c


def set_cookies(response: httpx.Response) -> dict[str, SimpleCookie]:
    out: dict[str, SimpleCookie] = {}
    for header in response.headers.get_list("set-cookie"):
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(header)
        for name in cookie:
            out[name] = cookie
    return out


async def cookie_login(browser: httpx.AsyncClient, email: str) -> httpx.Response:
    r = await browser.post(
        "/auth/login", json={"email": email, "password": PASSWORD}, headers=COOKIE_MODE
    )
    assert r.status_code == 200, r.text
    return r


def csrf(r: httpx.Response) -> dict[str, str]:
    return {"X-CSRF-Token": r.json()["csrf_token"]}


# --- login ------------------------------------------------------------------------------
async def test_cookie_login_keeps_the_refresh_token_out_of_the_body(
    browser: httpx.AsyncClient, make_user: UserFactory, settings: Settings
) -> None:
    await make_user("alice@example.com")
    r = await cookie_login(browser, "alice@example.com")
    body = r.json()
    assert body["refresh_token"] is None
    assert body["access_token"]
    assert r.headers["cache-control"] == "no-store"

    cookies = set_cookies(r)
    refresh = cookies["safs_refresh"]["safs_refresh"]
    assert refresh["httponly"] is True
    assert refresh["secure"] is True
    assert refresh["samesite"] == "strict"
    assert refresh["path"] == "/auth"
    assert int(refresh["max-age"]) == settings.refresh_token_ttl_seconds

    csrf_cookie = cookies["safs_csrf"]["safs_csrf"]
    assert csrf_cookie["httponly"] == ""  # readable by the page, for reloads
    assert csrf_cookie["path"] == "/"
    assert csrf_cookie.value == body["csrf_token"]
    assert body["csrf_token"] == csrf_token_for(settings, refresh.value)


async def test_json_login_is_unchanged(browser: httpx.AsyncClient, make_user: UserFactory) -> None:
    await make_user("alice@example.com")
    r = await browser.post("/auth/login", json={"email": "alice@example.com", "password": PASSWORD})
    assert r.json()["refresh_token"]
    assert r.json()["csrf_token"] is None
    assert "set-cookie" not in r.headers


# --- refresh ----------------------------------------------------------------------------
async def test_cookie_refresh_rotates_the_cookie_and_the_csrf_token(
    browser: httpx.AsyncClient, make_user: UserFactory
) -> None:
    await make_user("alice@example.com")
    first = await cookie_login(browser, "alice@example.com")
    old_cookie = browser.cookies["safs_refresh"]

    second = await browser.post("/auth/refresh", headers=csrf(first))
    assert second.status_code == 200, second.text
    assert second.json()["refresh_token"] is None
    assert second.json()["csrf_token"] != first.json()["csrf_token"]
    assert browser.cookies["safs_refresh"] != old_cookie

    # The rotated pair keeps working; the old CSRF token does not.
    assert (await browser.post("/auth/refresh", headers=csrf(second))).status_code == 200
    assert (await browser.post("/auth/refresh", headers=csrf(first))).status_code == 403


@pytest.mark.parametrize("header", [None, "", "0" * 64])
async def test_cookie_refresh_without_the_right_csrf_header_is_forbidden(
    browser: httpx.AsyncClient, make_user: UserFactory, header: str | None
) -> None:
    await make_user("alice@example.com")
    good = await cookie_login(browser, "alice@example.com")
    headers = {} if header is None else {"X-CSRF-Token": header}
    r = await browser.post("/auth/refresh", headers=headers)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"
    # Nothing was rotated: the real token still works.
    assert (await browser.post("/auth/refresh", headers=csrf(good))).status_code == 200


async def test_planted_cookie_with_its_own_csrf_value_is_rejected(
    browser: httpx.AsyncClient, make_user: UserFactory
) -> None:
    """A double-submit cookie an attacker can write is useless without the server key."""
    await make_user("alice@example.com")
    await cookie_login(browser, "alice@example.com")
    refresh = browser.cookies["safs_refresh"]
    browser.cookies.clear()
    r = await browser.post(
        "/auth/refresh",
        headers={
            "X-CSRF-Token": "attacker-chosen",
            "Cookie": f"safs_refresh={refresh}; safs_csrf=attacker-chosen",
        },
    )
    assert r.status_code == 403


async def test_refresh_with_neither_body_nor_cookie_is_unauthenticated(
    browser: httpx.AsyncClient,
) -> None:
    r = await browser.post("/auth/refresh")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "not_authenticated"


async def test_body_token_wins_over_the_cookie_and_needs_no_csrf(
    browser: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user("alice@example.com")
    await cookie_login(browser, "alice@example.com")
    r = await browser.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert r.status_code == 200
    assert r.json()["refresh_token"]  # JSON delivery for a JSON caller
    assert "set-cookie" not in r.headers


async def test_cookie_reuse_still_revokes_the_family(
    browser: httpx.AsyncClient, make_user: UserFactory, settings: Settings
) -> None:
    await make_user("alice@example.com")
    first = await cookie_login(browser, "alice@example.com")
    stolen = browser.cookies["safs_refresh"]
    second = await browser.post("/auth/refresh", headers=csrf(first))
    assert second.status_code == 200

    # Replaying the rotated-out cookie (with its matching CSRF token) trips reuse detection.
    browser.cookies.clear()
    r = await browser.post(
        "/auth/refresh",
        headers={
            "X-CSRF-Token": csrf_token_for(settings, stolen),
            "Cookie": f"safs_refresh={stolen}",
        },
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "refresh_token_reused"


# --- logout -----------------------------------------------------------------------------
async def test_cookie_logout_revokes_and_clears_cookies(
    browser: httpx.AsyncClient, make_user: UserFactory, settings: Settings
) -> None:
    await make_user("alice@example.com")
    r = await cookie_login(browser, "alice@example.com")
    raw = browser.cookies["safs_refresh"]

    out = await browser.post("/auth/logout", headers=csrf(r))
    assert out.status_code == 204
    cleared = set_cookies(out)
    assert cleared["safs_refresh"]["safs_refresh"]["max-age"] == "0"
    assert cleared["safs_csrf"]["safs_csrf"]["max-age"] == "0"
    assert "safs_refresh" not in browser.cookies

    # The session is revoked server-side too, not just forgotten by the browser.
    r = await browser.post("/auth/refresh", json={"refresh_token": raw})
    assert r.status_code == 401


async def test_cookie_logout_requires_csrf(
    browser: httpx.AsyncClient, make_user: UserFactory
) -> None:
    await make_user("alice@example.com")
    r = await cookie_login(browser, "alice@example.com")
    assert (await browser.post("/auth/logout")).status_code == 403
    assert (await browser.post("/auth/refresh", headers=csrf(r))).status_code == 200


async def test_json_logout_is_unchanged(browser: httpx.AsyncClient, make_user: UserFactory) -> None:
    user = await make_user("alice@example.com")
    r = await browser.post("/auth/logout", json={"refresh_token": user.refresh_token})
    assert r.status_code == 204
    assert "set-cookie" not in r.headers


# --- configuration ----------------------------------------------------------------------
async def test_cors_allows_credentials_and_the_csrf_header(
    resources: Resources, settings: Settings
) -> None:
    app = create_app(
        resources=resources,
        settings=settings.model_copy(update={"cors_origins": ["https://app.example.com"]}),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
        r = await c.options(
            "/auth/refresh",
            headers={
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "x-csrf-token",
            },
        )
    assert r.status_code == 200
    assert r.headers["access-control-allow-credentials"] == "true"
    assert r.headers["access-control-allow-origin"] == "https://app.example.com"
    assert "x-csrf-token" in r.headers["access-control-allow-headers"].lower()


def test_wildcard_cors_origin_is_refused() -> None:
    with pytest.raises(ValidationError, match="CORS_ORIGINS"):
        Settings(cors_origins=["*"])


def test_insecure_cookies_are_refused_in_production() -> None:
    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        Settings(
            environment="production",
            jwt_secret="x" * 40,
            cookie_secure=False,
        )
