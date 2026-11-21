"""TOTP two-factor auth: enrolment, sign-in challenge, recovery codes, admin reset."""

from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
import respx
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import func, select, update

from app.core import totp
from app.core.rbac import Role
from app.models import AuditEvent, RecoveryCode, User
from app.resources import Resources
from app.services.mfa import MfaService
from tests.api.test_oauth import _start, mock_github
from tests.conftest import PASSWORD, TestUser, UserFactory


@dataclass
class Clock:
    """Controls the TOTP clock. Starts 5 s into a 30 s step."""

    t: float = field(default_factory=lambda: (time.time() // 30) * 30 + 5)

    def advance(self, steps: int = 1) -> None:
        self.t += 30 * steps


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    c = Clock()
    monkeypatch.setattr("app.services.mfa.current_time", lambda: c.t)
    return c


@dataclass
class Enrolled:
    user: TestUser
    secret: bytes
    recovery_codes: list[str]

    def code(self, clock: Clock) -> str:
        return totp.totp(self.secret, clock.t)


def _secret(body: dict[str, Any]) -> bytes:
    b32 = body["secret"]
    return base64.b32decode(b32 + "=" * (-len(b32) % 8))


async def enroll(client: httpx.AsyncClient, user: TestUser, clock: Clock) -> Enrolled:
    r = await client.post("/auth/mfa/totp/setup", json={"password": PASSWORD}, headers=user.headers)
    assert r.status_code == 200, r.text
    secret = _secret(r.json())
    r = await client.post(
        "/auth/mfa/totp/enable", json={"code": totp.totp(secret, clock.t)}, headers=user.headers
    )
    assert r.status_code == 200, r.text
    clock.advance()  # the enable code's step is spent
    return Enrolled(user, secret, r.json()["recovery_codes"])


async def password_login(client: httpx.AsyncClient, email: str) -> httpx.Response:
    return await client.post("/auth/login", json={"email": email, "password": PASSWORD})


async def challenge_for(client: httpx.AsyncClient, email: str) -> str:
    r = await password_login(client, email)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mfa_required"] is True
    assert "access_token" not in body
    token: str = body["mfa_token"]
    return token


async def verify(client: httpx.AsyncClient, token: str, **factor: str) -> httpx.Response:
    return await client.post("/auth/mfa/verify", json={"mfa_token": token, **factor})


async def events(resources: Resources, action: str) -> list[AuditEvent]:
    async with resources.sessionmaker() as s:
        rows = await s.scalars(
            select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id)
        )
        return list(rows)


# --- enrolment --------------------------------------------------------------------------
async def test_setup_returns_a_seed_but_changes_nothing_until_enabled(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    user = await make_user()
    r = await client.post("/auth/mfa/totp/setup", json={"password": PASSWORD}, headers=user.headers)
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert len(_secret(body)) == 20
    assert body["otpauth_uri"].startswith("otpauth://totp/Secure%20File%20Share:")
    status = (await client.get("/auth/mfa", headers=user.headers)).json()
    assert status == {"enabled": False, "pending": True, "recovery_codes_remaining": 0}
    # Pending enrolment doesn't affect sign-in.
    assert "access_token" in (await password_login(client, user.email)).json()


async def test_seed_is_stored_encrypted(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    r = await client.post("/auth/mfa/totp/setup", json={"password": PASSWORD}, headers=user.headers)
    async with resources.sessionmaker() as s:
        stored = await s.scalar(select(User.totp_secret).where(User.email == user.email))
    assert stored is not None
    assert stored.startswith("v1:")
    assert r.json()["secret"] not in stored


async def test_setup_requires_the_password(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    for body in ({}, {"password": "wrong-password-entirely"}):
        r = await client.post("/auth/mfa/totp/setup", json=body, headers=user.headers)
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "invalid_credentials"
    failures = await events(resources, "auth.mfa_setup_started")
    assert [e.outcome for e in failures] == ["failure", "failure"]
    assert (await client.get("/auth/mfa", headers=user.headers)).json()["pending"] is False


async def test_setup_requires_a_verified_email(
    client: httpx.AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user(verified=False)
    r = await client.post("/auth/mfa/totp/setup", json={"password": PASSWORD}, headers=user.headers)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "email_not_verified"


async def test_oauth_only_account_can_enroll_without_a_password(
    client: httpx.AsyncClient, make_user: UserFactory, resources: Resources
) -> None:
    user = await make_user()
    async with resources.sessionmaker() as s:
        await s.execute(update(User).where(User.email == user.email).values(hashed_password=None))
        await s.commit()
    r = await client.post("/auth/mfa/totp/setup", json={}, headers=user.headers)
    assert r.status_code == 200, r.text


async def test_setup_requires_authentication(client: httpx.AsyncClient) -> None:
    assert (await client.post("/auth/mfa/totp/setup", json={})).status_code == 401
    assert (await client.get("/auth/mfa")).status_code == 401


async def test_enable_needs_a_valid_code_and_returns_recovery_codes(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    user = await make_user()
    r = await client.post("/auth/mfa/totp/setup", json={"password": PASSWORD}, headers=user.headers)
    secret = _secret(r.json())
    wrong = f"{(int(totp.totp(secret, clock.t)) + 1) % 1_000_000:06d}"
    r = await client.post("/auth/mfa/totp/enable", json={"code": wrong}, headers=user.headers)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_mfa_code"
    r = await client.post(
        "/auth/mfa/totp/enable", json={"code": totp.totp(secret, clock.t)}, headers=user.headers
    )
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    codes = r.json()["recovery_codes"]
    assert len(codes) == len(set(codes)) == resources.settings.mfa_recovery_code_count
    status = (await client.get("/auth/mfa", headers=user.headers)).json()
    assert status == {"enabled": True, "pending": False, "recovery_codes_remaining": 10}
    assert (await client.get("/users/me", headers=user.headers)).json()["mfa_enabled"] is True
    assert [e.outcome for e in await events(resources, "auth.mfa_enabled")] == ["success"]
    failed = await events(resources, "auth.mfa_failed")
    assert [(e.details["reason"], e.details["context"]) for e in failed] == [("bad_code", "enable")]


async def test_enable_without_setup_and_double_enrolment_conflict(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    user = await make_user()
    r = await client.post("/auth/mfa/totp/enable", json={"code": "123456"}, headers=user.headers)
    assert r.status_code == 409
    await enroll(client, user, clock)
    r = await client.post("/auth/mfa/totp/setup", json={"password": PASSWORD}, headers=user.headers)
    assert r.status_code == 409
    r = await client.post("/auth/mfa/totp/enable", json={"code": "123456"}, headers=user.headers)
    assert r.status_code == 409


@pytest.mark.parametrize("code", ["12345", "1234567", "abcdef", ""])
async def test_malformed_codes_are_rejected_by_validation(
    client: httpx.AsyncClient, make_user: UserFactory, code: str
) -> None:
    user = await make_user()
    r = await client.post("/auth/mfa/totp/enable", json={"code": code}, headers=user.headers)
    assert r.status_code == 422


# --- sign-in ----------------------------------------------------------------------------
async def test_login_with_mfa_returns_a_challenge_then_tokens(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    token = await challenge_for(client, enrolled.user.email)
    # The challenge grants nothing by itself.
    r = await client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    r = await verify(client, token, code=enrolled.code(clock))
    assert r.status_code == 200, r.text
    body = r.json()
    me = await client.get("/users/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.json()["email"] == enrolled.user.email
    # The refresh token works like any other.
    r = await client.post("/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert r.status_code == 200
    challenge = await events(resources, "auth.mfa_challenge_issued")
    assert challenge[-1].details == {"method": "password"}
    logins = await events(resources, "auth.login")
    assert logins[-1].details == {"mfa": "totp"}


async def test_a_code_is_accepted_only_once(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    code = enrolled.code(clock)
    assert (
        await verify(client, await challenge_for(client, enrolled.user.email), code=code)
    ).status_code == 200
    r = await verify(client, await challenge_for(client, enrolled.user.email), code=code)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_mfa_code"
    assert (await events(resources, "auth.mfa_failed"))[-1].details["reason"] == "replayed_code"
    # An older (still in-window) code is refused too: steps only move forward.
    clock.advance()
    older = totp.totp(enrolled.secret, clock.t - 60)
    r = await verify(client, await challenge_for(client, enrolled.user.email), code=older)
    assert r.status_code == 401
    r = await verify(
        client, await challenge_for(client, enrolled.user.email), code=enrolled.code(clock)
    )
    assert r.status_code == 200


async def test_concurrent_verifications_with_one_code_let_exactly_one_through(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    tokens = [await challenge_for(client, enrolled.user.email) for _ in range(5)]
    code = enrolled.code(clock)
    results = await asyncio.gather(*(verify(client, t, code=code) for t in tokens))
    assert sorted(r.status_code for r in results) == [200, 401, 401, 401, 401]


async def test_challenge_is_single_use(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    token = await challenge_for(client, enrolled.user.email)
    assert (await verify(client, token, code=enrolled.code(clock))).status_code == 200
    clock.advance()
    r = await verify(client, token, code=enrolled.code(clock))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_mfa_token"


async def test_a_wrong_code_leaves_the_challenge_usable(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    token = await challenge_for(client, enrolled.user.email)
    good = enrolled.code(clock)
    bad = f"{(int(good) + 1) % 1_000_000:06d}"
    assert (await verify(client, token, code=bad)).status_code == 401
    assert (await verify(client, token, code=good)).status_code == 200


async def test_second_factor_guesses_are_throttled(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    token = await challenge_for(client, enrolled.user.email)
    good = enrolled.code(clock)
    bad = f"{(int(good) + 1) % 1_000_000:06d}"
    for _ in range(resources.settings.mfa_max_attempts):
        assert (await verify(client, token, code=bad)).status_code == 401
    r = await verify(client, token, code=good)
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) >= 1
    # The throttle is per account, not per challenge.
    r = await verify(client, await challenge_for(client, enrolled.user.email), code=good)
    assert r.status_code == 429


async def test_success_resets_the_throttle(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    for _ in range(resources.settings.mfa_max_attempts):
        token = await challenge_for(client, enrolled.user.email)
        assert (await verify(client, token, code=enrolled.code(clock))).status_code == 200
        clock.advance()


async def test_logout_everywhere_kills_pending_challenges(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    token = await challenge_for(client, enrolled.user.email)
    assert (await client.post("/auth/logout-all", headers=enrolled.user.headers)).status_code == 204
    r = await verify(client, token, code=enrolled.code(clock))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_mfa_token"


async def test_garbage_or_forged_challenge_is_rejected(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    r = await verify(client, "x" * 40, code=enrolled.code(clock))
    assert r.status_code == 401
    # A real access token is not a challenge.
    r = await verify(client, enrolled.user.access_token, code=enrolled.code(clock))
    assert r.json()["error"]["code"] == "invalid_mfa_token"


async def test_challenge_for_user_who_since_disabled_mfa_is_rejected(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    token = await challenge_for(client, enrolled.user.email)
    async with resources.sessionmaker() as s:
        await s.execute(
            update(User).where(User.email == enrolled.user.email).values(totp_enabled_at=None)
        )
        await s.commit()
    r = await verify(client, token, code=enrolled.code(clock))
    assert r.json()["error"]["code"] == "invalid_mfa_token"


@pytest.mark.parametrize("factor", [{}, {"code": "123456", "recovery_code": "abcde-fghjk"}])
async def test_exactly_one_factor_is_required(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, factor: dict[str, str]
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    r = await verify(client, await challenge_for(client, enrolled.user.email), **factor)
    assert r.status_code == 422


async def test_cookie_delivery_on_verify(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    token = await challenge_for(client, enrolled.user.email)
    r = await client.post(
        "/auth/mfa/verify",
        json={"mfa_token": token, "code": enrolled.code(clock)},
        headers={"X-Token-Delivery": "cookie"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["refresh_token"] is None
    assert body["csrf_token"]
    assert r.cookies.get(resources.settings.refresh_cookie_name)


# --- recovery codes ---------------------------------------------------------------------
async def test_recovery_code_signs_in_once(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    code = enrolled.recovery_codes[0]
    typed = code.upper().replace("-", " ")  # as someone might type it from paper
    r = await verify(client, await challenge_for(client, enrolled.user.email), recovery_code=typed)
    assert r.status_code == 200, r.text
    assert (await events(resources, "auth.login"))[-1].details == {"mfa": "recovery_code"}
    r = await verify(client, await challenge_for(client, enrolled.user.email), recovery_code=code)
    assert r.status_code == 401
    assert (await events(resources, "auth.mfa_failed"))[-1].details["reason"] == "bad_recovery_code"
    status = (await client.get("/auth/mfa", headers=enrolled.user.headers)).json()
    assert status["recovery_codes_remaining"] == 9


async def test_recovery_codes_are_stored_hashed(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    async with resources.sessionmaker() as s:
        hashes = set(await s.scalars(select(RecoveryCode.code_hash)))
    assert len(hashes) == 10
    assert not hashes & {c.replace("-", "") for c in enrolled.recovery_codes}


async def test_another_users_recovery_code_does_not_work(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    a = await enroll(client, await make_user(), clock)
    b = await enroll(client, await make_user(), clock)
    r = await verify(
        client, await challenge_for(client, a.user.email), recovery_code=b.recovery_codes[0]
    )
    assert r.status_code == 401


async def test_regenerating_recovery_codes_invalidates_the_old_ones(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    r = await client.post(
        "/auth/mfa/recovery-codes",
        json={"code": enrolled.code(clock)},
        headers=enrolled.user.headers,
    )
    assert r.status_code == 200
    new_codes = r.json()["recovery_codes"]
    assert not set(new_codes) & set(enrolled.recovery_codes)
    old = await verify(
        client,
        await challenge_for(client, enrolled.user.email),
        recovery_code=enrolled.recovery_codes[0],
    )
    assert old.status_code == 401
    new = await verify(
        client, await challenge_for(client, enrolled.user.email), recovery_code=new_codes[0]
    )
    assert new.status_code == 200


async def test_regenerating_needs_mfa_enabled_and_a_totp_code(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    user = await make_user()
    r = await client.post("/auth/mfa/recovery-codes", json={"code": "123456"}, headers=user.headers)
    assert r.status_code == 409
    enrolled = await enroll(client, user, clock)
    r = await client.post(
        "/auth/mfa/recovery-codes",
        json={"code": enrolled.recovery_codes[0]},
        headers=user.headers,
    )
    assert r.status_code == 422  # a recovery code is not a TOTP code


# --- disabling --------------------------------------------------------------------------
async def test_disable_needs_password_and_second_factor(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    headers = enrolled.user.headers
    r = await client.post(
        "/auth/mfa/disable",
        json={"password": "wrong-password-entirely", "code": enrolled.code(clock)},
        headers=headers,
    )
    assert r.status_code == 401
    r = await client.post("/auth/mfa/disable", json={"password": PASSWORD}, headers=headers)
    assert r.status_code == 422
    r = await client.post(
        "/auth/mfa/disable",
        json={"password": PASSWORD, "recovery_code": enrolled.recovery_codes[1]},
        headers=headers,
    )
    assert r.status_code == 204
    assert (await client.get("/auth/mfa", headers=headers)).json() == {
        "enabled": False,
        "pending": False,
        "recovery_codes_remaining": 0,
    }
    assert "access_token" in (await password_login(client, enrolled.user.email)).json()
    async with resources.sessionmaker() as s:
        assert await s.scalar(select(func.count()).select_from(RecoveryCode)) == 0
    assert [e.outcome for e in await events(resources, "auth.mfa_disabled")] == [
        "failure",
        "success",
    ]
    r = await client.post(
        "/auth/mfa/disable", json={"password": PASSWORD, "code": "123456"}, headers=headers
    )
    assert r.status_code == 409


async def test_disable_with_totp_code(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    r = await client.post(
        "/auth/mfa/disable",
        json={"password": PASSWORD, "code": enrolled.code(clock)},
        headers=enrolled.user.headers,
    )
    assert r.status_code == 204


# --- admin reset ------------------------------------------------------------------------
async def test_admin_can_reset_a_users_mfa(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    admin = await make_user(role=Role.ADMIN)
    enrolled = await enroll(client, await make_user(), clock)
    r = await client.post(f"/admin/users/{enrolled.user.id}/mfa/reset", headers=admin.headers)
    assert r.status_code == 204
    # Their sessions are gone, and sign-in is password-only again.
    assert (await client.get("/users/me", headers=enrolled.user.headers)).status_code == 401
    assert "access_token" in (await password_login(client, enrolled.user.email)).json()
    [event] = await events(resources, "admin.mfa_reset")
    assert str(event.actor_id) == admin.id
    assert event.target_id == enrolled.user.id
    r = await client.post(f"/admin/users/{enrolled.user.id}/mfa/reset", headers=admin.headers)
    assert r.status_code == 409


async def test_admin_reset_permissions_and_unknown_user(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock
) -> None:
    admin = await make_user(role=Role.ADMIN)
    enrolled = await enroll(client, await make_user(), clock)
    member = await make_user()
    r = await client.post(f"/admin/users/{enrolled.user.id}/mfa/reset", headers=member.headers)
    assert r.status_code == 403
    r = await client.post(
        "/admin/users/00000000-0000-0000-0000-000000000000/mfa/reset", headers=admin.headers
    )
    assert r.status_code == 404


# --- OAuth ------------------------------------------------------------------------------
async def test_oauth_login_also_requires_the_second_factor(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    enrolled = await enroll(client, await make_user("octo@example.com"), clock)
    q = await _start(client, "github")
    with respx.mock as router:
        mock_github(router)
        r = await client.get(
            "/auth/oauth/github/callback", params={"code": "abc", "state": q["state"][0]}
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mfa_required"] is True
    assert "access_token" not in body
    assert (await events(resources, "auth.oauth_login")) == []
    r = await verify(client, body["mfa_token"], code=enrolled.code(clock))
    assert r.status_code == 200
    [event] = await events(resources, "auth.oauth_login")
    assert event.details == {"mfa": "totp", "provider": "github"}


# --- failure modes ----------------------------------------------------------------------
async def test_seed_copied_from_another_user_fails_closed(
    client: httpx.AsyncClient, make_user: UserFactory, clock: Clock, resources: Resources
) -> None:
    a = await enroll(client, await make_user(), clock)
    b = await enroll(client, await make_user(), clock)
    async with resources.sessionmaker() as s:
        b_secret = await s.scalar(select(User.totp_secret).where(User.email == b.user.email))
        await s.execute(update(User).where(User.email == a.user.email).values(totp_secret=b_secret))
        await s.commit()
    # Even b's valid code doesn't work on a's account: the ciphertext is bound to b.
    r = await verify(client, await challenge_for(client, a.user.email), code=b.code(clock))
    assert r.status_code == 401
    assert (await events(resources, "auth.mfa_failed"))[-1].details["reason"] == (
        "undecryptable_secret"
    )


async def test_redis_outage_fails_closed(
    client: httpx.AsyncClient,
    make_user: UserFactory,
    clock: Clock,
    resources: Resources,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    token = await challenge_for(client, enrolled.user.email)

    async def down(*args: object, **kwargs: object) -> None:
        raise RedisConnectionError("redis is down")

    monkeypatch.setattr(resources.redis, "exists", down)
    r = await verify(client, token, code=enrolled.code(clock))
    assert r.status_code == 503
    monkeypatch.undo()
    monkeypatch.setattr("app.services.mfa.current_time", lambda: clock.t)
    monkeypatch.setattr(resources.redis, "set", down)
    r = await verify(client, token, code=enrolled.code(clock))
    assert r.status_code == 503


async def test_losing_the_challenge_race_consumes_nothing(
    client: httpx.AsyncClient,
    make_user: UserFactory,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enrolled = await enroll(client, await make_user(), clock)
    token = await challenge_for(client, enrolled.user.email)

    async def already_taken(self: MfaService, claims: object) -> bool:
        return False

    with monkeypatch.context() as m:
        m.setattr(MfaService, "_consume_challenge", already_taken)
        r = await verify(client, token, code=enrolled.code(clock))
    assert r.json()["error"]["code"] == "invalid_mfa_token"
    # The code was rolled back with the request, so it still works on a fresh challenge.
    r = await verify(
        client, await challenge_for(client, enrolled.user.email), code=enrolled.code(clock)
    )
    assert r.status_code == 200
