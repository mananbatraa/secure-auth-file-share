"""Outgoing email. SMTP in deployments; a logging mailer when no SMTP host is set."""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

import structlog
from starlette.concurrency import run_in_threadpool

from app.core.config import Settings

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Mail:
    to: str
    subject: str
    body: str


class Mailer(Protocol):
    async def send(self, mail: Mail) -> None: ...


class LoggingMailer:
    """Development mailer: logs the message instead of sending it.

    The body (which may hold a verification link) is only logged outside production,
    so a misconfigured production deployment never writes live tokens to its logs.
    """

    def __init__(self, *, include_body: bool) -> None:
        self.include_body = include_body

    async def send(self, mail: Mail) -> None:
        log.warning(
            "email_not_sent_no_smtp",
            to=mail.to,
            subject=mail.subject,
            body=mail.body if self.include_body else "<redacted>",
        )


class SmtpMailer:
    def __init__(self, settings: Settings) -> None:
        if not settings.smtp_host:
            raise ValueError("SMTP_HOST is required for SmtpMailer")
        self.host = settings.smtp_host
        self.port = settings.smtp_port
        self.username = settings.smtp_username
        self.password = settings.smtp_password
        self.starttls = settings.smtp_starttls
        self.timeout = settings.smtp_timeout_seconds
        self.sender = settings.mail_from

    def build(self, mail: Mail) -> EmailMessage:
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = mail.to
        msg["Subject"] = mail.subject
        msg.set_content(mail.body)
        return msg

    def _send_sync(self, mail: Mail) -> None:
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
            if self.starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.username and self.password:
                smtp.login(self.username, self.password.get_secret_value())
            smtp.send_message(self.build(mail))

    async def send(self, mail: Mail) -> None:
        await run_in_threadpool(self._send_sync, mail)


def build_mailer(settings: Settings) -> Mailer:
    if settings.smtp_host:
        return SmtpMailer(settings)
    return LoggingMailer(include_body=settings.environment != "production")
