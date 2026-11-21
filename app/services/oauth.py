"""OAuth 2.0 authorization-code login (GitHub, Google) with state + PKCE.

State and the PKCE verifier live in Redis for a few minutes and are consumed with GETDEL,
so a callback can be completed exactly once.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import structlog
from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import NotFound, OAuthError, PermissionDenied
from app.core.security import new_opaque_token, utcnow
from app.models import OAuthAccount, RefreshToken, User
from app.services.audit import AuditAction, AuditLog
from app.services.auth import normalize_email

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    name: str
    authorize_url: str
    token_url: str
    scopes: tuple[str, ...]


PROVIDERS: dict[str, ProviderConfig] = {
    "github": ProviderConfig(
        name="github",
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",  # noqa: S106
        scopes=("read:user", "user:email"),
    ),
    "google": ProviderConfig(
        name="google",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",  # noqa: S106
        scopes=("openid", "email", "profile"),
    ),
}


@dataclass(frozen=True, slots=True)
class OAuthIdentity:
    provider: str
    account_id: str
    email: str
    email_verified: bool


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class OAuthService:
    def __init__(self, settings: Settings, redis: Redis, http: httpx.AsyncClient) -> None:
        self.settings = settings
        self.redis = redis
        self.http = http

    def _credentials(self, provider: str) -> tuple[ProviderConfig, str, str]:
        cfg = PROVIDERS.get(provider)
        if cfg is None:
            raise NotFound(f"Unknown OAuth provider '{provider}'")
        client_id = getattr(self.settings, f"{provider}_client_id")
        secret = getattr(self.settings, f"{provider}_client_secret")
        if not client_id or secret is None:
            raise NotFound(f"OAuth provider '{provider}' is not configured")
        return cfg, client_id, secret.get_secret_value()

    def redirect_uri(self, provider: str) -> str:
        base = self.settings.oauth_redirect_base_url.rstrip("/")
        return f"{base}/auth/oauth/{provider}/callback"

    async def authorization_url(self, provider: str) -> str:
        cfg, client_id, _ = self._credentials(provider)
        state = new_opaque_token(24)
        verifier = new_opaque_token(48)
        await self.redis.set(
            f"oauth:state:{state}",
            json.dumps({"provider": provider, "verifier": verifier}),
            ex=self.settings.oauth_state_ttl_seconds,
        )
        params = {
            "client_id": client_id,
            "redirect_uri": self.redirect_uri(provider),
            "response_type": "code",
            "scope": " ".join(cfg.scopes),
            "state": state,
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        if provider == "google":
            params["prompt"] = "select_account"
        return f"{cfg.authorize_url}?{urlencode(params)}"

    async def _consume_state(self, provider: str, state: str) -> str:
        raw = await self.redis.getdel(f"oauth:state:{state}")
        if raw is None:
            raise OAuthError("Invalid or expired OAuth state")
        data = json.loads(raw)
        if data.get("provider") != provider:
            raise OAuthError("OAuth state does not match provider")
        return str(data["verifier"])

    async def exchange_code(self, provider: str, code: str, state: str) -> OAuthIdentity:
        verifier = await self._consume_state(provider, state)
        cfg, client_id, client_secret = self._credentials(provider)
        try:
            resp = await self.http.post(
                cfg.token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri(provider),
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code_verifier": verifier,
                },
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            token = resp.json().get("access_token")
            if not token:
                raise OAuthError("Provider did not return an access token")
            if provider == "github":
                return await self._github_identity(token)
            return await self._google_identity(token)
        except httpx.HTTPError as exc:
            log.warning("oauth_provider_error", provider=provider, error=str(exc))
            raise OAuthError("OAuth provider request failed") from exc

    async def _get_json(self, url: str, token: str) -> Any:
        resp = await self.http.get(
            url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
        )
        resp.raise_for_status()
        return resp.json()

    async def _github_identity(self, token: str) -> OAuthIdentity:
        profile = await self._get_json("https://api.github.com/user", token)
        emails = await self._get_json("https://api.github.com/user/emails", token)
        primary = next(
            (e for e in emails if e.get("primary") and e.get("verified")),
            next((e for e in emails if e.get("verified")), None),
        )
        if primary is None:
            raise OAuthError("GitHub account has no verified email")
        return OAuthIdentity("github", str(profile["id"]), primary["email"], True)

    async def _google_identity(self, token: str) -> OAuthIdentity:
        info = await self._get_json("https://openidconnect.googleapis.com/v1/userinfo", token)
        return OAuthIdentity(
            "google", str(info["sub"]), info["email"], bool(info.get("email_verified"))
        )

    async def resolve_user(
        self, session: AsyncSession, identity: OAuthIdentity, audit: AuditLog | None = None
    ) -> User:
        """Find the linked user, link by verified email, or create a new account.

        A provider-verified email also verifies the local account. Linking to an existing
        account whose email was never verified is the classic *pre-account-takeover*
        setup (an attacker registers the victim's address with a password and waits for
        the victim to sign in with Google), so that unproven password is removed and its
        sessions revoked before the link is made.
        """
        audit = audit or AuditLog(session)
        link = await session.scalar(
            select(OAuthAccount).where(
                OAuthAccount.provider == identity.provider,
                OAuthAccount.provider_account_id == identity.account_id,
            )
        )
        if link is not None:
            user = await session.get(User, link.user_id)
            if user is None or not user.is_active:
                raise PermissionDenied("Account is disabled")
            if (
                not user.email_verified
                and identity.email_verified
                and normalize_email(identity.email) == user.email
            ):
                user.email_verified_at = utcnow()
                await session.commit()
            return user

        if not identity.email_verified:
            # Linking on an unverified email would let anyone claim an existing account.
            raise OAuthError("Email address is not verified with the provider")
        email = normalize_email(identity.email)
        user = await session.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(email=email, hashed_password=None, email_verified_at=utcnow())
            session.add(user)
            await session.flush()
        elif not user.is_active:
            raise PermissionDenied("Account is disabled")
        elif not user.email_verified:
            if user.hashed_password is not None:
                user.hashed_password = None
                user.token_version += 1
                await session.execute(
                    update(RefreshToken)
                    .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
                    .values(revoked_at=utcnow())
                )
                audit.record(
                    AuditAction.UNVERIFIED_PASSWORD_REMOVED,
                    actor_id=user.id,
                    target_type="user",
                    target_id=user.id,
                    provider=identity.provider,
                )
                log.warning("unverified_password_removed", user_id=str(user.id))
            user.email_verified_at = utcnow()
        session.add(
            OAuthAccount(
                user_id=user.id,
                provider=identity.provider,
                provider_account_id=identity.account_id,
            )
        )
        try:
            await session.commit()
        except IntegrityError as exc:  # concurrent first login for the same identity
            await session.rollback()
            raise OAuthError("Please retry the sign-in") from exc
        log.info("oauth_account_linked", provider=identity.provider, user_id=str(user.id))
        return user
