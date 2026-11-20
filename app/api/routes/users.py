from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.deps import AuthServiceDep, CurrentUser, SessionDep, require_permission
from app.core.errors import Conflict, NotFound
from app.core.rbac import Permission
from app.models import User
from app.schemas.auth import UserAdminUpdate, UserOut

router = APIRouter(tags=["users"])


@router.get("/users/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)


@router.get(
    "/admin/users",
    response_model=list[UserOut],
    dependencies=[Depends(require_permission(Permission.USERS_READ))],
)
async def list_users(
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[UserOut]:
    rows = await session.scalars(select(User).order_by(User.created_at).limit(limit).offset(offset))
    return [UserOut.model_validate(u) for u in rows]


@router.patch("/admin/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    body: UserAdminUpdate,
    session: SessionDep,
    auth: AuthServiceDep,
    admin: Annotated[User, Depends(require_permission(Permission.USERS_MANAGE))],
) -> UserOut:
    target = await session.get(User, user_id)
    if target is None:
        raise NotFound("User not found")
    if target.id == admin.id and (
        (body.role is not None and body.role != admin.role) or body.is_active is False
    ):
        raise Conflict("Admins cannot demote or deactivate themselves")
    changed = False
    if body.role is not None and body.role != target.role:
        target.role = body.role
        changed = True
    if body.is_active is not None and body.is_active != target.is_active:
        target.is_active = body.is_active
        changed = True
    if changed:
        # New role or deactivation must apply now, not when old tokens expire.
        await auth.revoke_all_sessions(target, commit=False)
    await session.commit()
    await session.refresh(target)
    return UserOut.model_validate(target)
