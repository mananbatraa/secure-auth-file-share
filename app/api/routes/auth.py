from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, status
from fastapi.responses import RedirectResponse, Response

from app.api.deps import (
    AuthServiceDep,
    ClientDep,
    CurrentUser,
    OAuthServiceDep,
    ResourcesDep,
    SessionDep,
)
from app.core.security import hash_opaque_token
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserOut,
)
from app.services.auth import IssuedTokens, normalize_email

router = APIRouter(prefix="/auth", tags=["auth"])


def _pair(tokens: IssuedTokens) -> TokenPair:
    return TokenPair(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.access_expires_in,
        refresh_expires_in=tokens.refresh_expires_in,
    )


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, auth: AuthServiceDep) -> UserOut:
    user = await auth.register(body.email, body.password)
    return UserOut.model_validate(user)


@router.post("/login", response_model=TokenPair)
async def login(
    body: LoginRequest, auth: AuthServiceDep, client: ClientDep, resources: ResourcesDep
) -> TokenPair:
    settings = resources.settings
    limiter = resources.limiter
    # Two buckets: per source IP (spraying many accounts) and per account (targeted
    # guessing from many IPs). Every attempt counts; success clears the account bucket.
    email_key = f"login:email:{hash_opaque_token(normalize_email(body.email))}"
    await limiter.enforce(
        f"login:ip:{client.ip_address}",
        limit=settings.login_max_attempts_per_ip,
        window_seconds=settings.login_window_seconds,
    )
    await limiter.enforce(
        email_key,
        limit=settings.login_max_attempts_per_email,
        window_seconds=settings.login_window_seconds,
    )
    tokens = await auth.login(body.email, body.password, client)
    await limiter.reset(email_key)
    return _pair(tokens)


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest, auth: AuthServiceDep, client: ClientDep) -> TokenPair:
    return _pair(await auth.rotate(body.refresh_token, client))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshRequest, auth: AuthServiceDep) -> Response:
    await auth.logout(body.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(user: CurrentUser, auth: AuthServiceDep) -> Response:
    await auth.revoke_all_sessions(user)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordRequest, user: CurrentUser, auth: AuthServiceDep
) -> Response:
    await auth.change_password(user, body.current_password, body.new_password)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/oauth/{provider}/authorize", status_code=status.HTTP_302_FOUND)
async def oauth_authorize(provider: str, oauth: OAuthServiceDep) -> RedirectResponse:
    url = await oauth.authorization_url(provider)
    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)


@router.get("/oauth/{provider}/callback", response_model=TokenPair)
async def oauth_callback(
    provider: str,
    code: Annotated[str, Query(min_length=1, max_length=2048)],
    state: Annotated[str, Query(min_length=1, max_length=256)],
    oauth: OAuthServiceDep,
    session: SessionDep,
    auth: AuthServiceDep,
    client: ClientDep,
) -> TokenPair:
    identity = await oauth.exchange_code(provider, code, state)
    user = await oauth.resolve_user(session, identity)
    tokens, _ = await auth.issue_tokens(user, client)
    return _pair(tokens)
