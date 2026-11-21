"""email verification (users.email_verified_at)

Accounts that already signed in through OAuth are backfilled as verified: linking
always required a provider-verified email. Password-only accounts start unverified.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-21 05:49:46.828114
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.execute(
        "UPDATE users SET email_verified_at = created_at "
        "WHERE id IN (SELECT user_id FROM oauth_accounts)"
    )


def downgrade() -> None:
    op.drop_column("users", "email_verified_at")
