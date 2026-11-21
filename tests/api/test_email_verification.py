"""Email verification: the link, what unverified accounts can't do, resends, OAuth."""

from __future__ import annotations

import uuid
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
import respx
from pydantic import SecretStr
from sqlalchemy import select, update

from app.core.security import create_access_token, create_email_verification_token
from app.models import AuditEvent, User
from app.resources import Resources
from tests.api.test_files import upload
from tests.api.test_oauth import _start, mock_github
from tests.conftest import PASSWORD, OutboxMailer, TestUser, UserFactory


def token_from(mailer: OutboxMailer, email: str) -> str:
    body = mailer.last_to(email).body
    link = next(line for line in body.splitlines() if line.startswith("http"))
    return parse_qs(urlparse(link).query)["token"][0]


async def verify(client: httpx.AsyncClient, token: str) -> httpx.Response:
    return await client.post("/auth/verify-email", json={"token": token})


async def audit_actions(resources: Resources) -> list[str]:
    async with resources.sessionmaker() as s:
        return list(await s.scalars(select(AuditEvent.action).order_by(AuditEvent.id)))


async def unverified(make_user: UserFactory, email: str = "new@example.com") -> TestUser:
    return await make_user(email, verified=False)


# --- the link ---------------------------------------------------------------------------
async def test_registration_mails_a_link_that_verifies_the_account(
    client: httpx.AsyncClient, mailer: OutboxMailer, resources: Resources
) -> None:
    r = await client.post("/auth/register", json={"email": "New@Example.com", "password": PASSWORD})
    assert r.status_code == 201
    assert r.json()["email_verified"] is False

    mail = mailer.last_to("new@example.com")
    assert mail.subject == "Confirm your email address"
    assert mail.body.count("http://localhost:3000/verify-email?token=") == 1

    r = await verify(client, token_from(mailer, "new@example.com"))
    assert r.status_code == 200, r.text
    assert r.json()["email_verified"] is True
    assert r.json()["email"] == "new@example.com"
    assert "auth.email_verified" in await audit_actions(resources)


async def test_verifying_twice_is_harmless_and_audited_once(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    await unverified(make_user)
    token = token_from(mailer, "new@example.com")
    assert (await verify(client, token)).status_code == 200
    assert (await verify(client, token)).status_code == 200
    assert (await audit_actions(resources)).count("auth.email_verified") == 1


async def test_users_me_reports_verification_state(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    user = await unverified(make_user)
    assert (await client.get("/users/me", headers=user.headers)).json()["email_verified"] is False
    await verify(client, token_from(mailer, user.email))
    assert (await client.get("/users/me", headers=user.headers)).json()["email_verified"] is True


@pytest.mark.parametrize(
    "token",
    ["not-a-token-at-all-xxxxxxxx", "a" * 40 + "." + "b" * 40 + "." + "c" * 40],
)
async def test_garbage_tokens_are_rejected(client: httpx.AsyncClient, token: str) -> None:
    r = await verify(client, token)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_verification_token"


async def test_expired_token_is_rejected(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await unverified(make_user)
    settings = resources.settings.model_copy(update={"email_verification_ttl_seconds": -10})
    token = create_email_verification_token(settings, user_id=uuid.UUID(user.id), email=user.email)
    assert (await verify(client, token)).status_code == 400


async def test_token_signed_with_another_key_is_rejected(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await unverified(make_user)
    settings = resources.settings.model_copy(
        update={"jwt_secret": SecretStr("someone-elses-secret-someone-elses-secret")}
    )
    token = create_email_verification_token(settings, user_id=uuid.UUID(user.id), email=user.email)
    assert (await verify(client, token)).status_code == 400


async def test_tokens_are_not_interchangeable_with_access_tokens(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    user = await unverified(make_user)
    # An access token is not a verification token...
    assert (await verify(client, user.access_token)).status_code == 400
    # ...and a verification token is not an access token.
    token = token_from(mailer, user.email)
    me = await client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 401


async def test_wrong_type_claim_is_rejected(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await unverified(make_user)
    s = resources.settings
    claims = jwt.decode(
        create_email_verification_token(s, user_id=uuid.UUID(user.id), email=user.email),
        options={"verify_signature": False},
    )
    forged = jwt.encode(
        {**claims, "type": "access"}, s.jwt_secret.get_secret_value(), algorithm="HS256"
    )
    assert (await verify(client, forged)).status_code == 400


async def test_link_stops_working_when_the_address_changes(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    user = await unverified(make_user)
    token = token_from(mailer, user.email)
    async with resources.sessionmaker() as s:
        await s.execute(update(User).where(User.email == user.email).values(email="x@example.com"))
        await s.commit()
    assert (await verify(client, token)).status_code == 400


async def test_deactivated_and_deleted_accounts_cannot_verify(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    user = await unverified(make_user)
    async with resources.sessionmaker() as s:
        await s.execute(update(User).where(User.email == user.email).values(is_active=False))
        await s.commit()
    assert (await verify(client, token_from(mailer, user.email))).status_code == 400

    ghost = create_email_verification_token(
        resources.settings, user_id=uuid.uuid4(), email="ghost@example.com"
    )
    assert (await verify(client, ghost)).status_code == 400


# --- what unverified accounts can't do --------------------------------------------------
async def test_unverified_users_cannot_upload_or_share(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    user = await unverified(make_user)
    friend = await make_user("friend@example.com")
    shared = (await upload(client, friend)).json()["id"]

    blocked = [
        await upload(client, user),
        await client.post(
            "/files/uploads",
            headers=user.headers,
            json={"filename": "a.bin", "content_type": "text/plain", "size_bytes": 3},
        ),
    ]
    for r in blocked:
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "email_not_verified"

    # Reading what others shared is fine.
    assert (await client.get("/users/me", headers=user.headers)).status_code == 200
    r = await client.post(
        f"/files/{shared}/permissions",
        headers=friend.headers,
        json={"email": user.email, "level": "editor"},
    )
    assert r.status_code == 201
    assert (await client.get(f"/files/{shared}/download", headers=user.headers)).status_code == 200
    # An unverified editor still can't hand the file on.
    r = await client.post(
        f"/files/{shared}/permissions",
        headers=user.headers,
        json={"email": "third@example.com", "level": "viewer"},
    )
    assert r.json()["error"]["code"] == "email_not_verified"

    await verify(client, token_from(mailer, user.email))
    assert (await upload(client, user)).status_code == 201


async def test_unverified_owner_cannot_create_share_links(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    owner = await make_user()
    file_id = (await upload(client, owner)).json()["id"]
    async with resources.sessionmaker() as s:
        await s.execute(
            update(User).where(User.email == owner.email).values(email_verified_at=None)
        )
        await s.commit()
    r = await client.post(
        f"/files/{file_id}/links", headers=owner.headers, json={"expires_in_seconds": 600}
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "email_not_verified"


async def test_verification_can_be_made_optional(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    resources.settings = resources.settings.model_copy(update={"require_verified_email": False})
    user = await unverified(make_user)
    assert (await upload(client, user)).status_code == 201


# --- resending --------------------------------------------------------------------------
async def test_resend_sends_a_fresh_link_and_is_capped(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    user = await unverified(make_user)
    for _ in range(3):
        r = await client.post("/auth/verify-email/resend", headers=user.headers)
        assert r.status_code == 202
    assert len([m for m in mailer.sent if m.to == user.email]) == 4  # + the sign-up mail
    r = await client.post("/auth/verify-email/resend", headers=user.headers)
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0
    assert (await verify(client, token_from(mailer, user.email))).status_code == 200


async def test_resend_requires_auth_and_an_unverified_address(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    assert (await client.post("/auth/verify-email/resend")).status_code == 401
    user = await make_user()
    r = await client.post("/auth/verify-email/resend", headers=user.headers)
    assert r.status_code == 409


async def test_mail_outage_does_not_block_sign_up(
    client: httpx.AsyncClient, mailer: OutboxMailer, resources: Resources
) -> None:
    mailer.fail = True
    r = await client.post(
        "/auth/register", json={"email": "alex.doe@example.com", "password": PASSWORD}
    )
    assert r.status_code == 201
    actions = await audit_actions(resources)
    assert "auth.register" in actions
    assert "auth.email_verification_sent" not in actions

    login = await client.post(
        "/auth/login", json={"email": "alex.doe@example.com", "password": PASSWORD}
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    r = await client.post("/auth/verify-email/resend", headers=headers)
    assert r.status_code == 503

    mailer.fail = False
    assert (await client.post("/auth/verify-email/resend", headers=headers)).status_code == 202
    assert (await verify(client, token_from(mailer, "alex.doe@example.com"))).status_code == 200


# --- OAuth ------------------------------------------------------------------------------
async def _github_login(client: httpx.AsyncClient) -> httpx.Response:
    q = await _start(client, "github")
    with respx.mock as router:
        mock_github(router)
        return await client.get(
            "/auth/oauth/github/callback", params={"code": "abc", "state": q["state"][0]}
        )


async def test_oauth_accounts_are_verified(client: httpx.AsyncClient) -> None:
    r = await _github_login(client)
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert (await client.get("/users/me", headers=headers)).json()["email_verified"] is True
    assert (await upload(client, TestUser("", "", r.json()["access_token"], ""))).status_code == 201


async def test_oauth_takes_over_an_unverified_squatted_account_safely(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    """Pre-account-takeover: someone registers the victim's address with a password, then
    the real owner signs in with GitHub. The squatter must lose all access."""
    squatter = await unverified(make_user, "octo@example.com")

    r = await _github_login(client)
    assert r.status_code == 200, r.text
    owner_headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    me = (await client.get("/users/me", headers=owner_headers)).json()
    assert me["id"] == squatter.id
    assert me["email_verified"] is True

    # The squatter's password, access token and refresh token are all dead.
    assert (await client.get("/users/me", headers=squatter.headers)).status_code == 401
    refresh = await client.post("/auth/refresh", json={"refresh_token": squatter.refresh_token})
    assert refresh.status_code == 401
    login = await client.post(
        "/auth/login", json={"email": "octo@example.com", "password": PASSWORD}
    )
    assert login.status_code == 401
    assert "auth.unverified_password_removed" in await audit_actions(resources)


async def test_oauth_keeps_the_password_of_a_verified_account(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    await make_user("octo@example.com")
    assert (await _github_login(client)).status_code == 200
    login = await client.post(
        "/auth/login", json={"email": "octo@example.com", "password": PASSWORD}
    )
    assert login.status_code == 200
    assert "auth.unverified_password_removed" not in await audit_actions(resources)


async def test_linked_oauth_login_verifies_a_still_unverified_account(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    assert (await _github_login(client)).status_code == 200
    async with resources.sessionmaker() as s:
        await s.execute(update(User).values(email_verified_at=None))  # e.g. pre-migration
        await s.commit()
    r = await _github_login(client)
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert (await client.get("/users/me", headers=headers)).json()["email_verified"] is True


def test_verification_tokens_carry_no_raw_email(resources: Resources) -> None:
    token = create_email_verification_token(
        resources.settings, user_id=uuid.uuid4(), email="private@example.com"
    )
    claims = jwt.decode(token, options={"verify_signature": False})
    assert "private@example.com" not in str(claims)
    assert claims["aud"].endswith(":email-verification")
    access, _ = create_access_token(
        resources.settings, user_id=uuid.uuid4(), role="member", token_version=0
    )
    assert jwt.decode(access, options={"verify_signature": False})["aud"] != claims["aud"]
    assert timedelta(seconds=claims["exp"] - claims["iat"]) == timedelta(hours=24)
