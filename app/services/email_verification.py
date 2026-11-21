"""Email verification for password sign-ups.

The link carries a signed, expiring token bound to the user id *and* a fingerprint of
the address it was mailed to, so it stops working if the address changes. No table is
needed: verifying is idempotent, so a token being usable more than once is harmless.
"""

from __future__ import annotations

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import Conflict, InvalidVerificationToken, ServiceUnavailable
from app.core.security import (
    create_email_verification_token,
    decode_email_verification_token,
    email_fingerprint,
    utcnow,
)
from app.models import User
from app.services.audit import AuditAction, AuditLog
from app.services.mailer import Mail, Mailer

log = structlog.get_logger(__name__)


class EmailVerificationService:
    def __init__(
        self, session: AsyncSession, settings: Settings, mailer: Mailer, audit: AuditLog
    ) -> None:
        self.session = session
        self.settings = settings
        self.mailer = mailer
        self.audit = audit

    def link_for(self, user: User) -> str:
        token = create_email_verification_token(self.settings, user_id=user.id, email=user.email)
        return self.settings.email_verification_url.replace("{token}", token)

    async def send(self, user: User) -> None:
        """Mail a verification link. Raises :class:`Conflict` if already verified."""
        if user.email_verified:
            raise Conflict("Email address is already verified")
        hours = max(1, self.settings.email_verification_ttl_seconds // 3600)
        body = (
            "Confirm your email address to start uploading and sharing files:\n\n"
            f"{self.link_for(user)}\n\n"
            f"The link expires in {hours} hour(s). If you did not sign up, ignore this email."
        )
        try:
            await self.mailer.send(
                Mail(to=user.email, subject="Confirm your email address", body=body)
            )
        except Exception as exc:
            log.exception("verification_email_failed", user_id=str(user.id))
            raise ServiceUnavailable("Could not send the email; try again later") from exc
        self.audit.record(
            AuditAction.EMAIL_VERIFICATION_SENT,
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
        )
        await self.session.commit()

    async def send_quietly(self, user: User) -> bool:
        """Send, but never fail the caller (registration succeeds even if mail is down)."""
        try:
            await self.send(user)
        except ServiceUnavailable:
            return False
        return True

    async def verify(self, token: str) -> User:
        user_id, fingerprint = decode_email_verification_token(self.settings, token)
        user = await self.session.get(User, user_id, with_for_update=True)
        if user is None or not user.is_active or email_fingerprint(user.email) != fingerprint:
            raise InvalidVerificationToken()
        if not user.email_verified:
            user.email_verified_at = utcnow()
            self.audit.record(
                AuditAction.EMAIL_VERIFIED, actor_id=user.id, target_type="user", target_id=user.id
            )
            log.info("email_verified", user_id=str(user.id))
        await self.session.commit()  # also releases the row lock when nothing changed
        return user
