from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.rbac import Role
from app.db.base import Base, TimestampMixin


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    # Null for accounts that only ever signed in through OAuth.
    hashed_password: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(
        Enum(Role, name="user_role", values_callable=lambda e: [m.value for m in e]),
        default=Role.MEMBER,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Embedded in access tokens; bumping it invalidates every outstanding access token
    # (logout-everywhere, password change, role change, deactivation).
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    # Set once the owner proves control of the address (link or a verified OAuth email).
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # TOTP second factor. The seed is AES-GCM encrypted (app.core.totp); it is set while
    # enrolment is pending and only counts once totp_enabled_at is set.
    totp_secret: Mapped[str | None] = mapped_column(String(255))
    totp_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Last accepted time step: a code is never accepted twice (RFC 6238 section 5.2).
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @property
    def email_verified(self) -> bool:
        return self.email_verified_at is not None

    @property
    def mfa_enabled(self) -> bool:
        return self.totp_enabled_at is not None


class OAuthAccount(TimestampMixin, Base):
    __tablename__ = "oauth_accounts"
    __table_args__ = (UniqueConstraint("provider", "provider_account_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    provider: Mapped[str] = mapped_column(String(32))
    provider_account_id: Mapped[str] = mapped_column(String(255))


class RecoveryCode(TimestampMixin, Base):
    """A single-use backup code for a user with TOTP enabled. Only a keyed hash is kept."""

    __tablename__ = "mfa_recovery_codes"
    __table_args__ = (UniqueConstraint("user_id", "code_hash"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # The unique (user_id, code_hash) index also serves lookups by user.
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(String(64))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
