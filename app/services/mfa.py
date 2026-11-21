"""TOTP two-factor authentication: enrolment, sign-in challenges, recovery codes.

Sign-in with a second factor is two requests. The first factor (password or OAuth)
returns a short-lived *challenge token* instead of tokens; ``/auth/mfa/verify`` trades
it plus a TOTP or recovery code for the real token pair. Guarantees:

* a TOTP code is accepted at most once (the last accepted time step is stored and
  checked under a row lock, so two concurrent requests with one code can't both win);
* a recovery code is consumed by a single conditional UPDATE, so it works once;
* a challenge token is single use (Redis ``SET NX`` on its id) and dies with
  ``token_version`` (logout-everywhere, password reset, admin action);
* second-factor guesses are throttled per account, everywhere a code is accepted;
* seeds are encrypted at rest with AES-GCM bound to the user id; recovery codes are
  stored as keyed hashes.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import NoReturn

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import totp
from app.core.config import Settings
from app.core.errors import (
    Conflict,
    EmailNotVerified,
    InvalidCredentials,
    InvalidMfaCode,
    InvalidMfaToken,
    ServiceUnavailable,
    ValidationFailed,
)
from app.core.security import (
    MfaChallengeClaims,
    create_mfa_challenge_token,
    decode_mfa_challenge_token,
    utcnow,
    verify_password,
)
from app.models import RecoveryCode, User
from app.services.audit import AuditAction, AuditLog, Outcome
from app.services.auth import AuthService
from app.services.rate_limit import SlidingWindowLimiter

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class TotpEnrolment:
    secret: str  # base32, for manual entry
    otpauth_uri: str  # for a QR code


@dataclass(frozen=True, slots=True)
class Challenge:
    token: str
    expires_in: int


@dataclass(frozen=True, slots=True)
class VerifiedChallenge:
    user: User
    claims: MfaChallengeClaims
    factor: str  # "totp" or "recovery_code"


def current_time() -> float:
    """The TOTP clock (a module function, so tests can move time)."""
    return time.time()


async def clear_mfa(session: AsyncSession, user: User) -> None:
    """Remove the second factor and its recovery codes (staged in the session)."""
    user.totp_secret = None
    user.totp_enabled_at = None
    user.totp_last_step = None
    await session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))


class MfaService:
    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        redis: Redis,
        limiter: SlidingWindowLimiter,
        audit: AuditLog,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.session = session
        self.settings = settings
        self.redis = redis
        self.limiter = limiter
        self.audit = audit
        self.clock = clock or current_time

    # --- status -------------------------------------------------------------------------
    async def recovery_codes_remaining(self, user: User) -> int:
        count = await self.session.scalar(
            select(func.count())
            .select_from(RecoveryCode)
            .where(RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None))
        )
        return int(count or 0)

    # --- enrolment ----------------------------------------------------------------------
    async def begin_setup(self, user: User, password: str | None) -> TotpEnrolment:
        """Generate a new (pending) seed. It only takes effect once :meth:`enable` runs.

        Requires a verified address: otherwise someone pre-registering a victim's email
        could attach their own authenticator to the account the victim later claims.
        Requires the password (when the account has one), so a stolen access token
        can't lock the owner out by enrolling the thief's phone.
        """
        if not user.email_verified:
            raise EmailNotVerified("Verify your email address before enabling two-factor auth")
        if user.mfa_enabled:
            raise Conflict("Two-factor authentication is already enabled")
        await self._require_password(user, password, AuditAction.MFA_SETUP_STARTED)
        secret = totp.new_secret()
        user.totp_secret = totp.encrypt_secret(self.settings, user.id, secret)
        user.totp_last_step = None
        self.audit.record(
            AuditAction.MFA_SETUP_STARTED, actor_id=user.id, target_type="user", target_id=user.id
        )
        await self.session.commit()
        return TotpEnrolment(
            secret=totp.secret_to_base32(secret),
            otpauth_uri=totp.provisioning_uri(
                secret, account=user.email, issuer=self.settings.mfa_issuer
            ),
        )

    async def enable(self, user: User, code: str) -> list[str]:
        """Confirm the pending seed with a first code; returns fresh recovery codes."""
        user = await self._lock(user)
        if user.mfa_enabled:
            await self.session.rollback()
            raise Conflict("Two-factor authentication is already enabled")
        if user.totp_secret is None:
            await self.session.rollback()
            raise Conflict("Start two-factor setup first")
        await self._check_totp(user, code, context="enable")
        user.totp_enabled_at = utcnow()
        codes = await self._replace_recovery_codes(user)
        self.audit.record(
            AuditAction.MFA_ENABLED, actor_id=user.id, target_type="user", target_id=user.id
        )
        await self.session.commit()
        await self._reset_throttle(user)
        log.info("mfa_enabled", user_id=str(user.id))
        return codes

    async def disable(
        self,
        user: User,
        *,
        password: str | None,
        code: str | None,
        recovery_code: str | None,
    ) -> None:
        """Turn the second factor off. Needs the password (if any) *and* a second factor."""
        if not user.mfa_enabled:
            raise Conflict("Two-factor authentication is not enabled")
        await self._require_password(user, password, AuditAction.MFA_DISABLED)
        user = await self._lock(user)
        await self._check_factor(user, code, recovery_code, context="disable")
        await clear_mfa(self.session, user)
        self.audit.record(
            AuditAction.MFA_DISABLED, actor_id=user.id, target_type="user", target_id=user.id
        )
        await self.session.commit()
        await self._reset_throttle(user)

    async def regenerate_recovery_codes(self, user: User, code: str) -> list[str]:
        """Replace all recovery codes. Needs a TOTP code: proof the device is at hand."""
        if not user.mfa_enabled:
            raise Conflict("Two-factor authentication is not enabled")
        user = await self._lock(user)
        await self._check_totp(user, code, context="regenerate")
        codes = await self._replace_recovery_codes(user)
        self.audit.record(
            AuditAction.MFA_RECOVERY_CODES_REGENERATED,
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
        )
        await self.session.commit()
        await self._reset_throttle(user)
        return codes

    async def admin_reset(self, admin: User, target: User) -> None:
        """For a user who lost both device and codes. Also ends all their sessions."""
        if not target.mfa_enabled and target.totp_secret is None:
            raise Conflict("Two-factor authentication is not enabled for this user")
        await clear_mfa(self.session, target)
        await AuthService(self.session, self.settings, self.audit).revoke_all_sessions(
            target, commit=False, audit=False
        )
        self.audit.record(
            AuditAction.MFA_RESET, actor_id=admin.id, target_type="user", target_id=target.id
        )
        await self.session.commit()
        log.warning("mfa_reset_by_admin", user_id=str(target.id), admin_id=str(admin.id))

    # --- sign-in challenge --------------------------------------------------------------
    async def issue_challenge(self, user: User, *, method: str) -> Challenge:
        """Called after the first factor passed, instead of issuing tokens."""
        token, _ = create_mfa_challenge_token(
            self.settings, user_id=user.id, token_version=user.token_version, method=method
        )
        self.audit.record(
            AuditAction.MFA_CHALLENGE,
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
            method=method,
        )
        await self.session.commit()
        return Challenge(token=token, expires_in=self.settings.mfa_challenge_ttl_seconds)

    async def verify_challenge(
        self, token: str, *, code: str | None, recovery_code: str | None
    ) -> VerifiedChallenge:
        """Check the challenge and the second factor. The caller issues the tokens and
        commits (its audit row and the consumed code commit together)."""
        claims = decode_mfa_challenge_token(self.settings, token)
        user = await self.session.get(User, claims.user_id, with_for_update=True)
        if (
            user is None
            or not user.is_active
            or user.token_version != claims.token_version
            or not user.mfa_enabled
        ):
            await self.session.rollback()
            raise InvalidMfaToken()
        if await self._challenge_used(claims):
            await self.session.rollback()
            raise InvalidMfaToken()
        factor = await self._check_factor(user, code, recovery_code, context="login")
        # Consume the challenge last: a wrong code leaves it usable for another try.
        if not await self._consume_challenge(claims):
            await self.session.rollback()
            raise InvalidMfaToken()
        await self._reset_throttle(user)
        return VerifiedChallenge(user=user, claims=claims, factor=factor)

    # --- internals ----------------------------------------------------------------------
    async def _lock(self, user: User) -> User:
        locked = await self.session.get(User, user.id, with_for_update=True, populate_existing=True)
        if locked is None:  # pragma: no cover - the caller just loaded this user
            raise InvalidCredentials()
        return locked

    async def _require_password(
        self, user: User, password: str | None, action: AuditAction
    ) -> None:
        if user.hashed_password is None:
            return  # OAuth-only account: the access token is all there is
        if not password or not verify_password(password, user.hashed_password):
            await self.audit.record_now(
                action,
                outcome=Outcome.FAILURE,
                actor_id=user.id,
                target_type="user",
                target_id=user.id,
                reason="bad_password",
            )
            raise InvalidCredentials()

    async def _throttle(self, user: User) -> None:
        await self.limiter.enforce(
            f"mfa:{user.id}",
            limit=self.settings.mfa_max_attempts,
            window_seconds=self.settings.mfa_window_seconds,
        )

    async def _reset_throttle(self, user: User) -> None:
        await self.limiter.reset(f"mfa:{user.id}")

    async def _check_factor(
        self, user: User, code: str | None, recovery_code: str | None, *, context: str
    ) -> str:
        if code is not None and recovery_code is None:
            await self._check_totp(user, code, context=context)
            return "totp"
        if recovery_code is None or code is not None:
            await self.session.rollback()
            raise ValidationFailed("Send exactly one of code or recovery_code")
        await self._throttle(user)
        used = await self.session.scalar(
            update(RecoveryCode)
            .where(
                RecoveryCode.user_id == user.id,
                RecoveryCode.code_hash
                == totp.hash_recovery_code(self.settings, user.id, recovery_code),
                RecoveryCode.used_at.is_(None),
            )
            .values(used_at=utcnow())
            .returning(RecoveryCode.id)
        )
        if used is None:
            await self._fail(user, "bad_recovery_code", context)
        return "recovery_code"

    async def _check_totp(self, user: User, code: str, *, context: str) -> None:
        await self._throttle(user)
        if user.totp_secret is None:  # pragma: no cover - callers check enrolment
            raise Conflict("Two-factor authentication is not set up")
        try:
            secret = totp.decrypt_secret(self.settings, user.id, user.totp_secret)
        except ValueError:
            log.error("totp_secret_undecryptable", user_id=str(user.id))
            await self._fail(user, "undecryptable_secret", context)
        step = totp.match_step(secret, code.strip(), self.clock())
        if step is None:
            await self._fail(user, "bad_code", context)
        if user.totp_last_step is not None and step <= user.totp_last_step:
            await self._fail(user, "replayed_code", context)
        user.totp_last_step = step

    async def _fail(self, user: User, reason: str, context: str) -> NoReturn:
        await self.audit.record_now(  # rolls back staged work and the row lock
            AuditAction.MFA_FAILED,
            outcome=Outcome.FAILURE,
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
            reason=reason,
            context=context,
        )
        raise InvalidMfaCode()

    async def _replace_recovery_codes(self, user: User) -> list[str]:
        await self.session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
        codes = [totp.new_recovery_code() for _ in range(self.settings.mfa_recovery_code_count)]
        self.session.add_all(
            RecoveryCode(
                id=uuid.uuid4(),
                user_id=user.id,
                code_hash=totp.hash_recovery_code(self.settings, user.id, c),
            )
            for c in codes
        )
        return codes

    def _used_key(self, claims: MfaChallengeClaims) -> str:
        return f"mfa-challenge-used:{claims.jti}"

    async def _challenge_used(self, claims: MfaChallengeClaims) -> bool:
        try:
            return bool(await self.redis.exists(self._used_key(claims)))
        except RedisError as exc:
            raise ServiceUnavailable("Sign-in temporarily unavailable") from exc

    async def _consume_challenge(self, claims: MfaChallengeClaims) -> bool:
        ttl = max(1, int((claims.expires_at - utcnow()).total_seconds()) + 1)
        try:
            return bool(await self.redis.set(self._used_key(claims), "1", nx=True, ex=ttl))
        except RedisError as exc:
            raise ServiceUnavailable("Sign-in temporarily unavailable") from exc
