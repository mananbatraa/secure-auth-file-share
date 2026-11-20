from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.deps import SessionDep, require_permission
from app.core.rbac import Permission
from app.models import AuditEvent
from app.schemas.audit import AuditEventOut, AuditPage

router = APIRouter(
    prefix="/admin/audit",
    tags=["admin"],
    dependencies=[Depends(require_permission(Permission.AUDIT_READ))],
)


@router.get("", response_model=AuditPage)
async def list_audit_events(
    session: SessionDep,
    action: Annotated[
        str | None,
        Query(max_length=64, description="Exact action, or a prefix ending in '.' (e.g. 'auth.')"),
    ] = None,
    outcome: Literal["success", "failure"] | None = None,
    actor_id: uuid.UUID | None = None,
    target_type: Annotated[str | None, Query(max_length=32)] = None,
    target_id: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    before_id: Annotated[int | None, Query(ge=1, description="Keyset cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AuditPage:
    """Newest first, keyset-paginated on the monotonically increasing event id."""
    stmt = select(AuditEvent)
    if action:
        if action.endswith("."):
            escaped = action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            stmt = stmt.where(AuditEvent.action.like(escaped + "%", escape="\\"))
        else:
            stmt = stmt.where(AuditEvent.action == action)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if actor_id:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    if target_type:
        stmt = stmt.where(AuditEvent.target_type == target_type)
    if target_id:
        stmt = stmt.where(AuditEvent.target_id == target_id)
    if since:
        stmt = stmt.where(AuditEvent.created_at >= since)
    if until:
        stmt = stmt.where(AuditEvent.created_at < until)
    if before_id:
        stmt = stmt.where(AuditEvent.id < before_id)
    rows = list(await session.scalars(stmt.order_by(AuditEvent.id.desc()).limit(limit + 1)))
    has_more = len(rows) > limit
    rows = rows[:limit]
    return AuditPage(
        items=[AuditEventOut.model_validate(r) for r in rows],
        next_before_id=rows[-1].id if has_more else None,
    )
