"""Password reset by email.

Requesting a reset never reveals whether an address has an account: the response is
the same, the mail is sent after the response (so timing does not tell either), and
the throttle is keyed on the address whether or not it exists.

The emailed token is a short-lived JWT bound to the user, the address and an HMAC of
the *current* password hash. Setting a new password changes that hash, so a token
works once; changing the password any other way also kills outstanding tokens.
Completing a reset revokes every session and access token, and proves ownership of
the mailbox, so it also verifies the address.
"""

from __future__ import annotations

import hmac

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import InvalidResetToken
from app.core.security import (
    create_password_reset_token,
    decode_password_reset_token,
    email_fingerprint,
    hash_password,
    password_fingerprint,
    utcnow,
)
from app.models import User
from app.services.audit import AuditAction, Outcome
from app.services.auth import AuthService, normalize_email, validate_password
from app.services.mailer import Mail, Mailer

log = structlog.get_logger(__name__)


class PasswordResetService:
    def __init__(self, auth: AuthService, settings: Settings) -> None:
        self.auth = auth
        self.session: AsyncSession = auth.session
        self.settings = settings

    def link_for(self, user: User) -> str:
        token = create_password_reset_token(
            self.settings,
            user_id=user.id,
            email=user.email,
            hashed_password=user.hashed_password,
        )
        return self.settings.password_reset_url.replace("{token}", token)

    async def request(self, email: str) -> Mail | None:
        """Prepare a reset mail for ``email``, or ``None`` if there is no such account.

        The caller sends the mail *after* responding, and responds identically either
        way. Both paths write one audit row, so they cost about the same.
        """
        email = normalize_email(email)
        user = await self.auth.get_user_by_email(email)
        if user is None or not user.is_active:
            await self.auth.audit.record_now(
                AuditAction.PASSWORD_RESET_REQUESTED,
                outcome=Outcome.FAILURE,
                actor_id=user.id if user else None,
                target_type="user",
                target_id=user.id if user else None,
                email=email,
                reason="unknown_email" if user is None else "inactive",
            )
            return None
        minutes = max(1, self.settings.password_reset_ttl_seconds // 60)
        body = (
            "Someone asked to reset the password for your account. To choose a new "
            "password, open this link:\n\n"
            f"{self.link_for(user)}\n\n"
            f"The link expires in {minutes} minute(s) and works once. Resetting signs you "
            "out everywhere. If you did not ask for this, ignore this email; your "
            "password has not changed."
        )
        self.auth.audit.record(
            AuditAction.PASSWORD_RESET_REQUESTED,
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
        )
        await self.session.commit()
        return Mail(to=user.email, subject="Reset your password", body=body)

    async def confirm(self, token: str, new_password: str) -> User:
        """Set a new password with a reset token. Raises :class:`InvalidResetToken`."""
        claims = decode_password_reset_token(self.settings, token)
        # Lock the row: two concurrent confirms with one token serialise, and the second
        # sees the new password hash and fails.
        user = await self.session.get(User, claims.user_id, with_for_update=True)
        if (
            user is None
            or not user.is_active
            or not hmac.compare_digest(email_fingerprint(user.email), claims.email_fingerprint)
            or not hmac.compare_digest(
                password_fingerprint(self.settings, user.hashed_password),
                claims.password_fingerprint,
            )
        ):
            await self.auth.audit.record_now(  # rolls back, releasing the lock
                AuditAction.PASSWORD_RESET,
                outcome=Outcome.FAILURE,
                actor_id=claims.user_id if user else None,
                target_type="user",
                target_id=claims.user_id,
                reason="stale_token" if user is not None and user.is_active else "no_user",
            )
            raise InvalidResetToken()
        try:
            validate_password(self.settings, new_password, email=user.email)
        except Exception:
            await self.session.rollback()
            raise
        user.hashed_password = hash_password(new_password)
        if not user.email_verified:
            user.email_verified_at = utcnow()  # they just proved they read this inbox
        await self.auth.revoke_all_sessions(user, commit=False, audit=False)
        self.auth.audit.record(
            AuditAction.PASSWORD_RESET, actor_id=user.id, target_type="user", target_id=user.id
        )
        await self.session.commit()
        log.info("password_reset", user_id=str(user.id))
        return user


async def deliver_quietly(mailer: Mailer, mail: Mail) -> None:
    """Background-task sender: a mail outage is logged, never surfaced to the requester."""
    try:
        await mailer.send(mail)
    except Exception:
        log.exception("password_reset_email_failed")
