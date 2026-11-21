"""Refresh-token delivery for browser clients: an HttpOnly cookie plus a CSRF token.

API clients keep receiving the refresh token in the JSON body. A browser client sends
``X-Token-Delivery: cookie`` on login and then:

* the refresh token lives in an ``HttpOnly; Secure; SameSite=Strict`` cookie scoped to
  ``/auth``, so page scripts (and any XSS) can never read it;
* the response carries a ``csrf_token`` (also set as a readable cookie for page
  reloads) that the client echoes in ``X-CSRF-Token`` on ``/auth/refresh`` and
  ``/auth/logout``. It is an HMAC of the refresh token, so it rotates with it and a
  cross-site page cannot produce it (signed double submit; SameSite=Strict is the
  first layer, this is the second).
"""

from __future__ import annotations

import hmac

from fastapi import Request, Response

from app.core.config import Settings
from app.core.errors import CsrfFailed, NotAuthenticated
from app.core.security import csrf_token_for
from app.schemas.auth import TokenPair
from app.services.auth import IssuedTokens

DELIVERY_HEADER = "x-token-delivery"
CSRF_HEADER = "x-csrf-token"
_REFRESH_COOKIE_PATH = "/auth"


def wants_cookie(request: Request) -> bool:
    return request.headers.get(DELIVERY_HEADER, "").strip().lower() == "cookie"


def deliver(
    tokens: IssuedTokens, response: Response, settings: Settings, *, cookie: bool
) -> TokenPair:
    """Build the response body, moving the refresh token into cookies if asked."""
    if not cookie:
        return TokenPair(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=tokens.access_expires_in,
            refresh_expires_in=tokens.refresh_expires_in,
        )
    csrf = csrf_token_for(settings, tokens.refresh_token)
    common = {
        "max_age": tokens.refresh_expires_in,
        "secure": settings.cookie_secure,
        "samesite": "strict",
        "domain": settings.cookie_domain,
    }
    response.set_cookie(
        settings.refresh_cookie_name,
        tokens.refresh_token,
        path=_REFRESH_COOKIE_PATH,
        httponly=True,
        **common,  # type: ignore[arg-type]
    )
    response.set_cookie(settings.csrf_cookie_name, csrf, path="/", httponly=False, **common)  # type: ignore[arg-type]
    response.headers["Cache-Control"] = "no-store"
    return TokenPair(
        access_token=tokens.access_token,
        refresh_token=None,
        expires_in=tokens.access_expires_in,
        refresh_expires_in=tokens.refresh_expires_in,
        csrf_token=csrf,
    )


def clear(response: Response, settings: Settings) -> None:
    for name, path in (
        (settings.refresh_cookie_name, _REFRESH_COOKIE_PATH),
        (settings.csrf_cookie_name, "/"),
    ):
        response.delete_cookie(
            name,
            path=path,
            domain=settings.cookie_domain,
            secure=settings.cookie_secure,
            httponly=name == settings.refresh_cookie_name,
            samesite="strict",
        )


def refresh_token_from(
    request: Request, body_token: str | None, settings: Settings
) -> tuple[str, bool]:
    """Return ``(refresh_token, from_cookie)``.

    A token in the body wins (API clients). Otherwise the cookie is used, and only with
    a matching CSRF header, because browsers attach cookies to cross-site requests.
    """
    if body_token is not None:
        return body_token, False
    cookie = request.cookies.get(settings.refresh_cookie_name)
    if not cookie:
        raise NotAuthenticated("No refresh token in the body or cookie")
    header = request.headers.get(CSRF_HEADER, "")
    if not header or not hmac.compare_digest(header, csrf_token_for(settings, cookie)):
        raise CsrfFailed()
    return cookie, True
