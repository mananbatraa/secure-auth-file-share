from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import InvalidToken, NotAuthenticated, PermissionDenied
from app.core.rbac import Permission, has_permission
from app.core.security import decode_access_token
from app.models import User
from app.resources import Resources
from app.services.auth import AuthService, ClientInfo
from app.services.files import FileService
from app.services.oauth import OAuthService

_bearer = HTTPBearer(auto_error=False)


def get_resources(request: Request) -> Resources:
    resources: Resources = request.app.state.resources
    return resources


ResourcesDep = Annotated[Resources, Depends(get_resources)]


def get_settings_dep(resources: ResourcesDep) -> Settings:
    return resources.settings


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


async def get_session(resources: ResourcesDep) -> AsyncIterator[AsyncSession]:
    async with resources.sessionmaker() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


def client_info(request: Request, settings: SettingsDep) -> ClientInfo:
    ip = request.client.host if request.client else None
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
    return ClientInfo(ip_address=ip, user_agent=request.headers.get("user-agent"))


ClientDep = Annotated[ClientInfo, Depends(client_info)]


def get_auth_service(session: SessionDep, settings: SettingsDep) -> AuthService:
    return AuthService(session, settings)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


def get_file_service(session: SessionDep, resources: ResourcesDep) -> FileService:
    return FileService(session, resources.storage, resources.settings)


FileServiceDep = Annotated[FileService, Depends(get_file_service)]


def get_oauth_service(resources: ResourcesDep) -> OAuthService:
    return OAuthService(resources.settings, resources.redis, resources.http)


OAuthServiceDep = Annotated[OAuthService, Depends(get_oauth_service)]


async def get_current_user(
    session: SessionDep,
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise NotAuthenticated()
    claims = decode_access_token(settings, credentials.credentials)
    user = await session.get(User, claims.user_id)
    # token_version makes logout-everywhere / role changes take effect immediately,
    # instead of waiting for outstanding access tokens to expire.
    if user is None or not user.is_active or user.token_version != claims.token_version:
        raise InvalidToken()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_permission(permission: Permission) -> Callable[[User], Awaitable[User]]:
    async def _check(user: CurrentUser) -> User:
        if not has_permission(user.role, permission):
            raise PermissionDenied()
        return user

    return _check
