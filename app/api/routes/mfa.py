"""Two-factor authentication (TOTP) endpoints: enrolment, sign-in verification."""

from __future__ import annotations

from fastapi import APIRouter, Request, status
from fastapi.responses import Response

from app.api import session_cookies
from app.api.deps import AuthServiceDep, ClientDep, CurrentUser, MfaServiceDep, SettingsDep
from app.schemas.auth import (
    MfaDisableRequest,
    MfaStatus,
    MfaVerifyRequest,
    RecoveryCodesOut,
    TokenPair,
    TotpCodeRequest,
    TotpSetupOut,
    TotpSetupRequest,
)
from app.services.audit import AuditAction

router = APIRouter(prefix="/auth/mfa", tags=["mfa"])


def _no_store(response: Response) -> None:
    # Seeds and recovery codes must not sit in browser or proxy caches.
    response.headers["Cache-Control"] = "no-store"


@router.get("", response_model=MfaStatus)
async def mfa_status(user: CurrentUser, mfa: MfaServiceDep) -> MfaStatus:
    return MfaStatus(
        enabled=user.mfa_enabled,
        pending=user.totp_secret is not None and not user.mfa_enabled,
        recovery_codes_remaining=await mfa.recovery_codes_remaining(user),
    )


@router.post("/totp/setup", response_model=TotpSetupOut)
async def totp_setup(
    body: TotpSetupRequest, user: CurrentUser, mfa: MfaServiceDep, response: Response
) -> TotpSetupOut:
    """Start enrolment: returns a new seed (show ``otpauth_uri`` as a QR code).

    Nothing changes for sign-in until ``/totp/enable`` confirms a code. Calling this
    again before then replaces the pending seed.
    """
    enrolment = await mfa.begin_setup(user, body.password)
    _no_store(response)
    return TotpSetupOut(secret=enrolment.secret, otpauth_uri=enrolment.otpauth_uri)


@router.post("/totp/enable", response_model=RecoveryCodesOut)
async def totp_enable(
    body: TotpCodeRequest, user: CurrentUser, mfa: MfaServiceDep, response: Response
) -> RecoveryCodesOut:
    """Confirm enrolment with a code from the app. Recovery codes are shown only now."""
    codes = await mfa.enable(user, body.code)
    _no_store(response)
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/recovery-codes", response_model=RecoveryCodesOut)
async def regenerate_recovery_codes(
    body: TotpCodeRequest, user: CurrentUser, mfa: MfaServiceDep, response: Response
) -> RecoveryCodesOut:
    """Replace every recovery code (old ones stop working). Needs a TOTP code."""
    codes = await mfa.regenerate_recovery_codes(user, body.code)
    _no_store(response)
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(body: MfaDisableRequest, user: CurrentUser, mfa: MfaServiceDep) -> Response:
    """Turn two-factor auth off: the password (if any) plus a TOTP or recovery code."""
    await mfa.disable(
        user, password=body.password, code=body.code, recovery_code=body.recovery_code
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/verify", response_model=TokenPair)
async def mfa_verify(
    body: MfaVerifyRequest,
    mfa: MfaServiceDep,
    auth: AuthServiceDep,
    client: ClientDep,
    settings: SettingsDep,
    request: Request,
    response: Response,
) -> TokenPair:
    """Second sign-in step: the challenge from login plus a TOTP or recovery code.

    Honours ``X-Token-Delivery: cookie`` like ``/auth/login``.
    """
    verified = await mfa.verify_challenge(
        body.mfa_token, code=body.code, recovery_code=body.recovery_code
    )
    method = verified.claims.method
    details = {"mfa": verified.factor}
    action = AuditAction.LOGIN
    if method.startswith("oauth:"):
        action = AuditAction.OAUTH_LOGIN
        details["provider"] = method.removeprefix("oauth:")
    tokens = await auth.complete_login(verified.user, client, action=action, details=details)
    return session_cookies.deliver(
        tokens, response, settings, cookie=session_cookies.wants_cookie(request)
    )
