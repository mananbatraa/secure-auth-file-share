"""indexes on expires_at for the cleanup job

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-21 05:43:57.449031
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        op.f("ix_file_permissions_expires_at"), "file_permissions", ["expires_at"], unique=False
    )
    op.create_index(
        op.f("ix_refresh_tokens_expires_at"), "refresh_tokens", ["expires_at"], unique=False
    )
    op.create_index(op.f("ix_share_links_expires_at"), "share_links", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_share_links_expires_at"), table_name="share_links")
    op.drop_index(op.f("ix_refresh_tokens_expires_at"), table_name="refresh_tokens")
    op.drop_index(op.f("ix_file_permissions_expires_at"), table_name="file_permissions")
