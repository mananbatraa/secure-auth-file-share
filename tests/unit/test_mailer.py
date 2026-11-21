from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.services import mailer as mailer_module
from app.services.mailer import LoggingMailer, Mail, SmtpMailer, build_mailer

MAIL = Mail(to="bob@example.com", subject="Hi", body="secret link")


class FakeSMTP:
    instances: list[FakeSMTP] = []  # noqa: RUF012

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.calls: list[tuple[str, Any]] = []
        FakeSMTP.instances.append(self)

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *exc: object) -> None:
        self.calls.append(("quit", None))

    def starttls(self, context: Any) -> None:
        self.calls.append(("starttls", context))

    def login(self, user: str, password: str) -> None:
        self.calls.append(("login", (user, password)))

    def send_message(self, msg: Any) -> None:
        self.calls.append(("send", msg))


@pytest.fixture
def fake_smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSMTP]:
    FakeSMTP.instances = []
    monkeypatch.setattr("app.services.mailer.smtplib.SMTP", FakeSMTP)
    return FakeSMTP


async def test_smtp_mailer_uses_starttls_and_login(fake_smtp: type[FakeSMTP]) -> None:
    settings = Settings(
        smtp_host="smtp.example.com",
        smtp_port=2525,
        smtp_username="apikey",
        smtp_password=SecretStr("pw"),
        mail_from="Files <files@example.com>",
    )
    await SmtpMailer(settings).send(MAIL)

    (smtp,) = fake_smtp.instances
    assert (smtp.host, smtp.port, smtp.timeout) == ("smtp.example.com", 2525, 10.0)
    names = [c[0] for c in smtp.calls]
    assert names == ["starttls", "login", "send", "quit"]
    assert smtp.calls[1][1] == ("apikey", "pw")
    msg = smtp.calls[2][1]
    assert (msg["From"], msg["To"], msg["Subject"]) == (
        "Files <files@example.com>",
        "bob@example.com",
        "Hi",
    )
    assert msg.get_content().strip() == "secret link"


async def test_smtp_mailer_without_tls_or_auth(fake_smtp: type[FakeSMTP]) -> None:
    settings = Settings(smtp_host="mailpit", smtp_port=1025, smtp_starttls=False)
    await SmtpMailer(settings).send(MAIL)
    assert [c[0] for c in fake_smtp.instances[0].calls] == ["send", "quit"]


def test_smtp_mailer_needs_a_host() -> None:
    with pytest.raises(ValueError, match="SMTP_HOST"):
        SmtpMailer(Settings())


def test_build_mailer_picks_smtp_only_when_configured() -> None:
    assert isinstance(build_mailer(Settings(smtp_host="smtp.example.com")), SmtpMailer)
    dev = build_mailer(Settings())
    assert isinstance(dev, LoggingMailer)
    assert dev.include_body is True
    prod = build_mailer(Settings(environment="production", jwt_secret=SecretStr("x" * 40)))
    assert isinstance(prod, LoggingMailer)
    assert prod.include_body is False


@pytest.mark.parametrize("include_body", [True, False])
async def test_logging_mailer_redacts_the_body_in_production(
    include_body: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def capture(event: str, **kw: Any) -> None:
        seen.update(kw, event=event)

    monkeypatch.setattr(mailer_module.log, "warning", capture)
    await LoggingMailer(include_body=include_body).send(MAIL)
    assert seen["event"] == "email_not_sent_no_smtp"
    assert seen["to"] == "bob@example.com"
    assert (seen["body"] == "secret link") is include_body


def test_verification_url_must_have_a_token_placeholder() -> None:
    with pytest.raises(ValueError, match="EMAIL_VERIFICATION_URL"):
        Settings(email_verification_url="https://app.example.com/verify")
