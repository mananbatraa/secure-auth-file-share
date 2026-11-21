"""Registration, login, and refresh-token rotation with reuse detection."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import structlog
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import (
    Conflict,
    InvalidCredentials,
    InvalidToken,
    TokenReuseDetected,
    ValidationFailed,
)
from app.core.rbac import Role
from app.core.security import (
    burn_password_check,
    create_access_token,
    hash_opaque_token,
    hash_password,
    new_opaque_token,
    utcnow,
    verify_password,
)
from app.models import RefreshToken, User
from app.services.audit import AuditAction, AuditLog, Outcome

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ClientInfo:
    ip_address: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True, slots=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int


def normalize_email(email: str) -> str:
    return email.strip().lower()


def validate_password(settings: Settings, password: str, *, email: str | None = None) -> None:
    if len(password) < settings.password_min_length:
        raise ValidationFailed(
            f"Password must be at least {settings.password_min_length} characters"
        )
    if password.strip() != password:
        raise ValidationFailed("Password must not start or end with whitespace")
    if email and normalize_email(email).split("@")[0] in password.lower():
        raise ValidationFailed("Password must not contain your email name")


class AuthService:
    def __init__(
        self, session: AsyncSession, settings: Settings, audit: AuditLog | None = None
    ) -> None:
        self.session = session
        self.settings = settings
        self.audit = audit or AuditLog(session)

    # --- accounts -----------------------------------------------------------------------
    async def register(self, email: str, password: str, *, role: Role = Role.MEMBER) -> User:
        email = normalize_email(email)
        validate_password(self.settings, password, email=email)
        user = User(
            id=uuid.uuid4(), email=email, hashed_password=hash_password(password), role=role
        )
        self.session.add(user)
        self.audit.record(
            AuditAction.REGISTER, actor_id=user.id, target_type="user", target_id=user.id
        )
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise Conflict("An account with this email already exists") from exc
        log.info("user_registered", user_id=str(user.id))
        return user

    async def get_user_by_email(self, email: str) -> User | None:
        return await self.session.scalar(select(User).where(User.email == normalize_email(email)))

    async def authenticate(self, email: str, password: str) -> User:
        user = await self.get_user_by_email(email)
        if user is None:
            burn_password_check(password)
            await self._login_failed(email, None, "unknown_email")
            raise InvalidCredentials()
        if not verify_password(password, user.hashed_password):
            await self._login_failed(email, user.id, "bad_password")
            raise InvalidCredentials()
        if not user.is_active:
            await self._login_failed(email, user.id, "inactive")
            raise InvalidCredentials()
        return user

    async def _login_failed(self, email: str, user_id: uuid.UUID | None, reason: str) -> None:
        await self.audit.record_now(
            AuditAction.LOGIN,
            outcome=Outcome.FAILURE,
            actor_id=user_id,
            target_type="user",
            target_id=user_id,
            email=normalize_email(email),
            reason=reason,
        )

    async def change_password(self, user: User, current: str, new: str) -> None:
        if not verify_password(current, user.hashed_password):
            await self.audit.record_now(
                AuditAction.PASSWORD_CHANGED,
                outcome=Outcome.FAILURE,
                actor_id=user.id,
                target_type="user",
                target_id=user.id,
                reason="bad_password",
            )
            raise InvalidCredentials()
        validate_password(self.settings, new, email=user.email)
        user.hashed_password = hash_password(new)
        await self.revoke_all_sessions(user, commit=False, audit=False)
        self.audit.record(
            AuditAction.PASSWORD_CHANGED, actor_id=user.id, target_type="user", target_id=user.id
        )
        await self.session.commit()

    # --- tokens -------------------------------------------------------------------------
    async def issue_tokens(
        self,
        user: User,
        client: ClientInfo,
        *,
        family_id: uuid.UUID | None = None,
        commit: bool = True,
    ) -> tuple[IssuedTokens, RefreshToken]:
        access, _ = create_access_token(
            self.settings, user_id=user.id, role=user.role.value, token_version=user.token_version
        )
        raw_refresh = new_opaque_token()
        row = RefreshToken(
            id=uuid.uuid4(),
            user_id=user.id,
            family_id=family_id or uuid.uuid4(),
            token_hash=hash_opaque_token(raw_refresh),
            expires_at=utcnow() + timedelta(seconds=self.settings.refresh_token_ttl_seconds),
            ip_address=client.ip_address,
            user_agent=(client.user_agent or "")[:512] or None,
        )
        self.session.add(row)
        if commit:
            await self.session.commit()
        tokens = IssuedTokens(
            access_token=access,
            refresh_token=raw_refresh,
            access_expires_in=self.settings.access_token_ttl_seconds,
            refresh_expires_in=self.settings.refresh_token_ttl_seconds,
        )
        return tokens, row

    async def complete_login(
        self,
        user: User,
        client: ClientInfo,
        *,
        action: AuditAction = AuditAction.LOGIN,
        details: dict[str, Any] | None = None,
    ) -> IssuedTokens:
        """Record the sign-in and open a session (commits)."""
        self.audit.record(
            action, actor_id=user.id, target_type="user", target_id=user.id, **(details or {})
        )
        tokens, _ = await self.issue_tokens(user, client)
        log.info("login_succeeded", user_id=str(user.id), **(details or {}))
        return tokens

    async def rotate(self, raw_refresh: str, client: ClientInfo) -> IssuedTokens:
        """Exchange a refresh token for a new pair.

        The row is locked ``FOR UPDATE`` so two concurrent refreshes with the same token
        serialise: the first rotates it, the second sees it as used and trips reuse
        detection (revoking the family), exactly as a stolen-token replay would.
        """
        now = utcnow()
        row = await self.session.scalar(
            select(RefreshToken)
            .where(RefreshToken.token_hash == hash_opaque_token(raw_refresh))
            .with_for_update()
        )
        if row is None:
            raise InvalidToken()
        if row.used_at is not None or row.revoked_at is not None:
            await self._revoke_family(row.family_id)
            self.audit.record(
                AuditAction.REFRESH_REUSE,
                outcome=Outcome.FAILURE,
                actor_id=row.user_id,
                target_type="token_family",
                target_id=row.family_id,
            )
            await self.session.commit()
            log.warning(
                "refresh_token_reuse_detected",
                user_id=str(row.user_id),
                family_id=str(row.family_id),
                ip=client.ip_address,
            )
            raise TokenReuseDetected()
        if row.expires_at <= now:
            await self.session.rollback()
            raise InvalidToken()
        user = await self.session.get(User, row.user_id)
        if user is None or not user.is_active:
            await self._revoke_family(row.family_id)
            await self.session.commit()
            raise InvalidToken()

        tokens, new_row = await self.issue_tokens(
            user, client, family_id=row.family_id, commit=False
        )
        await self.session.flush()
        row.used_at = now
        row.replaced_by_id = new_row.id
        await self.session.commit()
        return tokens

    async def logout(self, raw_refresh: str) -> None:
        """Revoke the session (token family) the refresh token belongs to. Idempotent."""
        row = await self.session.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hash_opaque_token(raw_refresh))
        )
        if row is not None:
            await self._revoke_family(row.family_id)
            self.audit.record(
                AuditAction.LOGOUT,
                actor_id=row.user_id,
                target_type="token_family",
                target_id=row.family_id,
            )
            await self.session.commit()

    async def revoke_all_sessions(
        self, user: User, *, commit: bool = True, audit: bool = True
    ) -> None:
        """Revoke every refresh token and invalidate outstanding access tokens."""
        await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        user.token_version += 1
        if audit:
            self.audit.record(
                AuditAction.LOGOUT_ALL, actor_id=user.id, target_type="user", target_id=user.id
            )
        if commit:
            await self.session.commit()

    async def _revoke_family(self, family_id: uuid.UUID) -> None:
        await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
