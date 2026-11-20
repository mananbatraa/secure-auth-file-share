from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    action: str
    outcome: str
    actor_id: uuid.UUID | None
    target_type: str | None
    target_id: str | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    details: dict[str, Any]


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    # Pass as ``before_id`` to fetch the next (older) page; null when there is none.
    next_before_id: int | None
