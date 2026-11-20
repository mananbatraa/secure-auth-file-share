from __future__ import annotations

from typing import Any

import structlog

from app.services.audit import AuditAction, AuditLog, Outcome


class FakeSession:
    def __init__(self, *, fail_commit: bool = False) -> None:
        self.added: list[Any] = []
        self.calls: list[str] = []
        self.fail_commit = fail_commit

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.calls.append("commit")
        if self.fail_commit:
            raise RuntimeError("database is down")

    async def rollback(self) -> None:
        self.calls.append("rollback")


def test_record_stages_event_with_context() -> None:
    session = FakeSession()
    audit = AuditLog(session, ip_address="198.51.100.4", user_agent="x" * 600)  # type: ignore[arg-type]
    structlog.contextvars.bind_contextvars(request_id="rid-1")
    try:
        event = audit.record(AuditAction.LOGIN, target_id="abc", reason=None, kept=1)
    finally:
        structlog.contextvars.clear_contextvars()
    assert session.added == [event]
    assert event.outcome == "success"
    assert event.request_id == "rid-1"
    assert event.ip_address == "198.51.100.4"
    assert event.user_agent == "x" * 512
    assert event.details == {"kept": 1}  # None-valued details are dropped


async def test_record_now_rolls_back_pending_work_first() -> None:
    session = FakeSession()
    await AuditLog(session).record_now(AuditAction.LOGIN, outcome=Outcome.FAILURE)  # type: ignore[arg-type]
    assert session.calls == ["rollback", "commit"]


async def test_record_now_never_raises_when_the_write_fails() -> None:
    session = FakeSession(fail_commit=True)
    await AuditLog(session).record_now(AuditAction.LINK_REJECTED, outcome=Outcome.FAILURE)  # type: ignore[arg-type]
    assert session.calls == ["rollback", "commit", "rollback"]
