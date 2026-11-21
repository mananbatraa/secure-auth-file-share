from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Query, status
from fastapi.responses import RedirectResponse, Response

from app.api.deps import (
    AuthServiceDep,
    ClientDep,
    CurrentUser,
    EmailVerificationDep,
    OAuthServiceDep,
    PasswordResetDep,
    ResourcesDep,
    SessionDep,
)
from app.core.errors import Conflict, RateLimited
from app.core.security import hash_opaque_token
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserOut,
    VerifyEmailRequest,
)
from app.services.audit import AuditAction, Outcome
from app.services.auth import IssuedTokens, normalize_email
from app.services.password_reset import deliver_quietly

router = APIRouter(prefix="/auth", tags=["auth"])


def _pair(tokens: IssuedTokens) -> TokenPair:
    return TokenPair(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.access_expires_in,
        refresh_expires_in=tokens.refresh_expires_in,
    )


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest, auth: AuthServiceDep, verification: EmailVerificationDep
) -> UserOut:
    user = await auth.register(body.email, body.password)
    # A mail outage must not fail sign-up; the user can ask for a new link later.
    await verification.send_quietly(user)
    return UserOut.model_validate(user)


@router.post("/verify-email", response_model=UserOut)
async def verify_email(body: VerifyEmailRequest, verification: EmailVerificationDep) -> UserOut:
    """Confirm an address with the token from the emailed link. Idempotent."""
    return UserOut.model_validate(await verification.verify(body.token))


@router.post("/verify-email/resend", status_code=status.HTTP_202_ACCEPTED)
async def resend_verification(
    user: CurrentUser, verification: EmailVerificationDep, resources: ResourcesDep
) -> dict[str, str]:
    settings = resources.settings
    if user.email_verified:
        raise Conflict("Email address is already verified")
    # Each resend is an email to a third-party inbox: cap it per account.
    await resources.limiter.enforce(
        f"verify-resend:{user.id}",
        limit=settings.email_verification_resend_limit,
        window_seconds=settings.email_verification_resend_window_seconds,
    )
    await verification.send(user)
    return {"status": "sent"}


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
async def request_password_reset(
    body: PasswordResetRequest,
    reset: PasswordResetDep,
    client: ClientDep,
    resources: ResourcesDep,
    background: BackgroundTasks,
) -> dict[str, str]:
    """Email a reset link if the account exists. The answer is the same either way."""
    settings = resources.settings
    email = normalize_email(body.email)
    # Keyed on the address whether or not it exists, so a 429 reveals nothing either.
    await resources.limiter.enforce(
        f"pwreset:ip:{client.ip_address}",
        limit=settings.password_reset_max_per_ip,
        window_seconds=settings.password_reset_window_seconds,
    )
    await resources.limiter.enforce(
        f"pwreset:email:{hash_opaque_token(email)}",
        limit=settings.password_reset_max_per_email,
        window_seconds=settings.password_reset_window_seconds,
    )
    mail = await reset.request(email)
    if mail is not None:
        # Sent after the response, so response time doesn't reveal the account exists.
        background.add_task(deliver_quietly, resources.mailer, mail)
    return {"status": "accepted"}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_password_reset(body: PasswordResetConfirm, reset: PasswordResetDep) -> Response:
    """Set a new password with the emailed token. Signs the user out everywhere."""
    await reset.confirm(body.token, body.new_password)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/login", response_model=TokenPair)
async def login(
    body: LoginRequest, auth: AuthServiceDep, client: ClientDep, resources: ResourcesDep
) -> TokenPair:
    settings = resources.settings
    limiter = resources.limiter
    # Two buckets: per source IP (spraying many accounts) and per account (targeted
    # guessing from many IPs). Every attempt counts; success clears the account bucket.
    email_key = f"login:email:{hash_opaque_token(normalize_email(body.email))}"
    try:
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
    except RateLimited:
        await auth.audit.record_now(
            AuditAction.LOGIN_THROTTLED,
            outcome=Outcome.FAILURE,
            email=normalize_email(body.email),
        )
        raise
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
    user = await oauth.resolve_user(session, identity, auth.audit)
    auth.audit.record(
        AuditAction.OAUTH_LOGIN,
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        provider=identity.provider,
    )
    tokens, _ = await auth.issue_tokens(user, client)
    return _pair(tokens)
