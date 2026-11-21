"""Password reset: no account enumeration, single-use tokens, sessions revoked."""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from pydantic import ValidationError
from sqlalchemy import select, update

from app.core.config import Settings
from app.core.security import (
    create_email_verification_token,
    create_password_reset_token,
    utcnow,
)
from app.models import AuditEvent, User
from app.resources import Resources
from tests.conftest import PASSWORD, OutboxMailer, TestUser, UserFactory

NEW_PASSWORD = "a-brand-new-passphrase-42"


def reset_token_from(mailer: OutboxMailer, email: str) -> str:
    mail = mailer.last_to(email)
    assert mail.subject == "Reset your password"
    link = next(line for line in mail.body.splitlines() if line.startswith("http"))
    assert link.startswith("http://localhost:3000/reset-password?token=")
    return parse_qs(urlparse(link).query)["token"][0]


async def request_reset(client: httpx.AsyncClient, email: str) -> httpx.Response:
    return await client.post("/auth/password-reset/request", json={"email": email})


async def confirm(
    client: httpx.AsyncClient, token: str, password: str = NEW_PASSWORD
) -> httpx.Response:
    return await client.post(
        "/auth/password-reset/confirm", json={"token": token, "new_password": password}
    )


async def login(client: httpx.AsyncClient, email: str, password: str) -> httpx.Response:
    return await client.post("/auth/login", json={"email": email, "password": password})


async def audit_rows(resources: Resources, action: str) -> list[AuditEvent]:
    async with resources.sessionmaker() as s:
        rows = await s.scalars(
            select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id)
        )
        return list(rows)


async def get_user(resources: Resources, email: str) -> User:
    async with resources.sessionmaker() as s:
        user = await s.scalar(select(User).where(User.email == email))
        assert user is not None
        return user


async def mailed_token(client: httpx.AsyncClient, mailer: OutboxMailer, email: str) -> str:
    r = await request_reset(client, email)
    assert r.status_code == 202, r.text
    return reset_token_from(mailer, email.lower())


# --- the happy path ---------------------------------------------------------------------
async def test_reset_sets_the_new_password_and_signs_out_everywhere(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    user = await make_user("alice@example.com")
    token = await mailed_token(client, mailer, "Alice@Example.com")  # normalised

    r = await confirm(client, token)
    assert r.status_code == 204, r.text

    assert (await login(client, user.email, PASSWORD)).status_code == 401
    assert (await login(client, user.email, NEW_PASSWORD)).status_code == 200
    # Outstanding access and refresh tokens die with the old password.
    assert (await client.get("/users/me", headers=user.headers)).status_code == 401
    r = await client.post("/auth/refresh", json={"refresh_token": user.refresh_token})
    assert r.status_code == 401

    requested = await audit_rows(resources, "auth.password_reset_requested")
    assert [(e.outcome, e.target_id) for e in requested] == [("success", user.id)]
    done = await audit_rows(resources, "auth.password_reset")
    assert [(e.outcome, e.actor_id) for e in done] == [("success", uuid.UUID(user.id))]


async def test_mail_says_how_long_the_link_lasts(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    await make_user("alice@example.com")
    await request_reset(client, "alice@example.com")
    body = mailer.last_to("alice@example.com").body
    assert "expires in 30 minute(s)" in body
    assert "ignore this email" in body


# --- no account enumeration -------------------------------------------------------------
async def test_unknown_address_gets_the_same_answer_and_no_mail(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    await make_user("alice@example.com")
    known = await request_reset(client, "alice@example.com")
    unknown = await request_reset(client, "nobody@example.com")

    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json() == {"status": "accepted"}
    assert [m.to for m in mailer.sent if m.subject == "Reset your password"] == [
        "alice@example.com"
    ]
    rows = await audit_rows(resources, "auth.password_reset_requested")
    failure = next(e for e in rows if e.outcome == "failure")
    assert failure.details == {"email": "nobody@example.com", "reason": "unknown_email"}


async def test_deactivated_account_gets_no_mail(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    user = await make_user("alice@example.com")
    async with resources.sessionmaker() as s:
        await s.execute(update(User).where(User.email == user.email).values(is_active=False))
        await s.commit()
    sent_before = len(mailer.sent)

    assert (await request_reset(client, user.email)).status_code == 202
    assert len(mailer.sent) == sent_before
    rows = await audit_rows(resources, "auth.password_reset_requested")
    assert rows[-1].details["reason"] == "inactive"


async def test_mail_outage_is_invisible_to_the_requester(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    await make_user("alice@example.com")
    mailer.fail = True
    r = await request_reset(client, "alice@example.com")
    assert r.status_code == 202
    assert r.json() == {"status": "accepted"}


async def test_requests_are_throttled_per_address_even_unknown_ones(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    await make_user("alice@example.com")
    limit = resources.settings.password_reset_max_per_email
    for email in ("alice@example.com", "nobody@example.com"):
        for _ in range(limit):
            assert (await request_reset(client, email)).status_code == 202
        r = await request_reset(client, email.upper())  # same bucket after normalising
        assert r.status_code == 429
        assert int(r.headers["Retry-After"]) >= 1
        assert r.json()["error"]["code"] == "rate_limited"


async def test_requests_are_throttled_per_ip(
    client: httpx.AsyncClient, resources: Resources
) -> None:
    for i in range(resources.settings.password_reset_max_per_ip):
        assert (await request_reset(client, f"user{i}@example.com")).status_code == 202
    assert (await request_reset(client, "another@example.com")).status_code == 429


# --- the token --------------------------------------------------------------------------
async def test_token_works_once(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    await make_user("alice@example.com")
    token = await mailed_token(client, mailer, "alice@example.com")
    assert (await confirm(client, token)).status_code == 204

    r = await confirm(client, token, "yet-another-passphrase-7")
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_reset_token"
    assert (await login(client, "alice@example.com", NEW_PASSWORD)).status_code == 200
    failures = [
        e for e in await audit_rows(resources, "auth.password_reset") if e.outcome == "failure"
    ]
    assert [e.details["reason"] for e in failures] == ["stale_token"]


async def test_using_one_link_kills_the_others(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    await make_user("alice@example.com")
    first = await mailed_token(client, mailer, "alice@example.com")
    second = await mailed_token(client, mailer, "alice@example.com")
    assert (await confirm(client, second)).status_code == 204
    assert (await confirm(client, first)).status_code == 400


async def test_changing_the_password_kills_outstanding_links(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    user = await make_user("alice@example.com")
    token = await mailed_token(client, mailer, user.email)
    r = await client.post(
        "/auth/change-password",
        headers=user.headers,
        json={"current_password": PASSWORD, "new_password": "changed-the-usual-way-9"},
    )
    assert r.status_code == 204
    assert (await confirm(client, token)).status_code == 400


async def test_link_dies_if_the_address_changes(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    await make_user("alice@example.com")
    token = await mailed_token(client, mailer, "alice@example.com")
    async with resources.sessionmaker() as s:
        await s.execute(
            update(User).where(User.email == "alice@example.com").values(email="a2@example.com")
        )
        await s.commit()
    assert (await confirm(client, token)).status_code == 400


async def test_link_dies_if_the_account_is_deactivated(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    await make_user("alice@example.com")
    token = await mailed_token(client, mailer, "alice@example.com")
    async with resources.sessionmaker() as s:
        await s.execute(
            update(User).where(User.email == "alice@example.com").values(is_active=False)
        )
        await s.commit()
    assert (await confirm(client, token)).status_code == 400


async def test_expired_token_is_rejected(
    client: httpx.AsyncClient, make_user: UserFactory, settings: Settings, resources: Resources
) -> None:
    await make_user("alice@example.com")
    user = await get_user(resources, "alice@example.com")
    payload = {
        "sub": str(user.id),
        "eml": "x",
        "pwd": "x",
        "type": "password_reset",
        "iss": settings.jwt_issuer,
        "aud": f"{settings.jwt_audience}:password-reset",
        "iat": utcnow() - timedelta(hours=2),
        "exp": utcnow() - timedelta(hours=1),
    }
    token = jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm="HS256")
    assert (await confirm(client, token)).status_code == 400


async def test_token_for_a_missing_user_is_rejected(
    client: httpx.AsyncClient, settings: Settings, resources: Resources
) -> None:
    token = create_password_reset_token(
        settings, user_id=uuid.uuid4(), email="ghost@example.com", hashed_password=None
    )
    assert (await confirm(client, token)).status_code == 400
    rows = await audit_rows(resources, "auth.password_reset")
    assert rows[-1].details["reason"] == "no_user"
    assert rows[-1].actor_id is None


@pytest.mark.parametrize("kind", ["verification", "access", "forged", "garbage"])
async def test_other_tokens_cannot_reset_a_password(
    client: httpx.AsyncClient,
    make_user: UserFactory,
    settings: Settings,
    resources: Resources,
    kind: str,
) -> None:
    test_user = await make_user("alice@example.com")
    user = await get_user(resources, "alice@example.com")
    tokens = {
        "verification": create_email_verification_token(
            settings, user_id=user.id, email=user.email
        ),
        "access": test_user.access_token,
        "forged": jwt.encode(
            {
                "sub": str(user.id),
                "type": "password_reset",
                "aud": f"{settings.jwt_audience}:password-reset",
                "iss": settings.jwt_issuer,
                "exp": utcnow() + timedelta(minutes=5),
                "iat": utcnow(),
                "eml": "x",
                "pwd": "x",
            },
            "another-secret-that-is-long-enough-000000",
            algorithm="HS256",
        ),
        "garbage": "not-a-jwt-at-all-but-long-enough",
    }
    r = await confirm(client, tokens[kind])
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_reset_token"
    assert (await login(client, user.email, PASSWORD)).status_code == 200


async def test_reset_token_is_not_an_access_token(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    await make_user("alice@example.com")
    token = await mailed_token(client, mailer, "alice@example.com")
    r = await client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


async def test_weak_password_is_refused_and_the_link_still_works(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    await make_user("alice@example.com")
    token = await mailed_token(client, mailer, "alice@example.com")
    r = await confirm(client, token, "short")
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_failed"
    assert (await login(client, "alice@example.com", PASSWORD)).status_code == 200
    assert (await confirm(client, token)).status_code == 204


async def test_concurrent_confirms_with_one_token_let_exactly_one_through(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    await make_user("alice@example.com")
    token = await mailed_token(client, mailer, "alice@example.com")
    passwords = [f"racing-passphrase-number-{i}" for i in range(5)]
    results = await asyncio.gather(*(confirm(client, token, p) for p in passwords))
    codes = sorted(r.status_code for r in results)
    assert codes == [204, 400, 400, 400, 400]
    winner = passwords[[r.status_code for r in results].index(204)]
    assert (await login(client, "alice@example.com", winner)).status_code == 200


# --- account states ---------------------------------------------------------------------
async def test_reset_verifies_an_unverified_address(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer
) -> None:
    user: TestUser = await make_user("fresh@example.com", verified=False)
    token = await mailed_token(client, mailer, user.email)
    assert (await confirm(client, token)).status_code == 204
    new = (await login(client, user.email, NEW_PASSWORD)).json()
    me = await client.get("/users/me", headers={"Authorization": f"Bearer {new['access_token']}"})
    assert me.json()["email_verified"] is True


async def test_password_less_account_can_set_a_password(
    client: httpx.AsyncClient, make_user: UserFactory, mailer: OutboxMailer, resources: Resources
) -> None:
    """An OAuth-only account proves the mailbox and gains a password."""
    await make_user("oauth@example.com")
    async with resources.sessionmaker() as s:
        await s.execute(
            update(User).where(User.email == "oauth@example.com").values(hashed_password=None)
        )
        await s.commit()
    token = await mailed_token(client, mailer, "oauth@example.com")
    assert (await confirm(client, token)).status_code == 204
    assert (await login(client, "oauth@example.com", NEW_PASSWORD)).status_code == 200


# --- configuration ----------------------------------------------------------------------
def test_reset_url_must_contain_a_token_placeholder() -> None:
    with pytest.raises(ValidationError, match="PASSWORD_RESET_URL"):
        Settings(password_reset_url="http://localhost:3000/reset")
