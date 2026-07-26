"""conversation key backups

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-23 00:00:00.000000

Adds `conversation_key_backups`: a password-recoverable backup of each
participant's per-conversation message key (extends FR-054's identity-key
recovery to the 1:1 conversation symmetric key). Opaque to the server — it
stores and relays the wrapped blob but never decrypts it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "conversation_key_backups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "conversation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("wrapped_key", sa.LargeBinary(), nullable=False),
        sa.Column("wrap_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("wrap_kdf_salt", sa.LargeBinary(), nullable=False),
        sa.Column("wrap_kdf_params", sa.String(length=64), nullable=False),
        sa.Column("wrap_alg", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("conversation_id", "user_id", name="uq_conversation_key_backup"),
    )
    op.create_index(
        "ix_conversation_key_backups_conversation_id",
        "conversation_key_backups",
        ["conversation_id"],
    )
    op.create_index(
        "ix_conversation_key_backups_user_id",
        "conversation_key_backups",
        ["user_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_conversation_key_backups_user_id", table_name="conversation_key_backups")
    op.drop_index(
        "ix_conversation_key_backups_conversation_id", table_name="conversation_key_backups"
    )
    op.drop_table("conversation_key_backups")
