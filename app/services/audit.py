"""Append-only audit trail of security-relevant events.

Events are added to the caller's session, so a successful action and its audit row
commit (or roll back) together. Failure events, where the business transaction has
nothing to commit, are written with :meth:`AuditLog.record_now`.
"""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditEvent

log = structlog.get_logger(__name__)


class AuditAction(StrEnum):
    REGISTER = "auth.register"
    LOGIN = "auth.login"
    LOGIN_THROTTLED = "auth.login_throttled"
    OAUTH_LOGIN = "auth.oauth_login"
    REFRESH_REUSE = "auth.refresh_reuse_detected"
    LOGOUT = "auth.logout"
    LOGOUT_ALL = "auth.logout_all"
    EMAIL_VERIFICATION_SENT = "auth.email_verification_sent"
    EMAIL_VERIFIED = "auth.email_verified"
    UNVERIFIED_PASSWORD_REMOVED = "auth.unverified_password_removed"  # noqa: S105
    PASSWORD_CHANGED = "auth.password_changed"  # noqa: S105 - an event name
    PASSWORD_RESET_REQUESTED = "auth.password_reset_requested"  # noqa: S105
    PASSWORD_RESET = "auth.password_reset"  # noqa: S105
    MFA_SETUP_STARTED = "auth.mfa_setup_started"
    MFA_ENABLED = "auth.mfa_enabled"
    MFA_DISABLED = "auth.mfa_disabled"
    MFA_CHALLENGE = "auth.mfa_challenge_issued"
    MFA_FAILED = "auth.mfa_failed"
    MFA_RECOVERY_CODES_REGENERATED = "auth.mfa_recovery_codes_regenerated"
    USER_UPDATED = "admin.user_updated"
    MFA_RESET = "admin.mfa_reset"
    FILE_UPLOADED = "file.uploaded"
    FILE_UPLOAD_REJECTED = "file.upload_rejected"
    FILE_RENAMED = "file.renamed"
    FILE_DELETED = "file.deleted"
    FILE_DOWNLOAD_URL = "file.download_url_issued"
    GRANT_CREATED = "file.grant_created"
    GRANT_REVOKED = "file.grant_revoked"
    LINK_CREATED = "file.link_created"
    LINK_REVOKED = "file.link_revoked"
    LINK_REDEEMED = "file.link_redeemed"
    LINK_REJECTED = "file.link_rejected"
    MAINTENANCE_CLEANUP = "maintenance.cleanup"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class AuditLog:
    def __init__(
        self,
        session: AsyncSession,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        self.session = session
        self.ip_address = ip_address
        self.user_agent = (user_agent or "")[:512] or None

    def record(
        self,
        action: AuditAction,
        *,
        actor_id: uuid.UUID | None = None,
        target_type: str | None = None,
        target_id: uuid.UUID | str | None = None,
        outcome: Outcome = Outcome.SUCCESS,
        **details: Any,
    ) -> AuditEvent:
        """Stage an event in the current transaction (committed by the caller)."""
        request_id = structlog.contextvars.get_contextvars().get("request_id")
        event = AuditEvent(
            action=action.value,
            outcome=outcome.value,
            actor_id=actor_id,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            request_id=str(request_id)[:64] if request_id else None,
            details={k: v for k, v in details.items() if v is not None},
        )
        self.session.add(event)
        return event

    async def record_now(self, action: AuditAction, **kwargs: Any) -> None:
        """Record and commit immediately, for failures that abort the request.

        Any pending, uncommitted work in the session is rolled back first so a failed
        action can never be committed by accident alongside its audit row.
        """
        await self.session.rollback()
        self.record(action, **kwargs)
        try:
            await self.session.commit()
        except Exception:  # never let auditing turn a 4xx into a 500
            await self.session.rollback()
            log.exception("audit_write_failed", action=action.value)
