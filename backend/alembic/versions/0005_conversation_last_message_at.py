"""conversation last_message_at

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-22 05:00:00.000000

Adds `conversations.last_message_at` (FR-058): the timestamp of the most recent
message in a conversation, used to order the conversation list newest-first and
to display the last-activity time. The server holds ONLY this timestamp — the
latest-message *preview* is decrypted client-side (FR-051); the server stores
only ciphertext and cannot produce a readable preview.

Nullable (conversations with no messages keep NULL; `list_for_user` falls back
to `created_at`). Backfilled from `MAX(messages.sent_at)` per conversation so
existing conversations order correctly immediately after upgrade.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "conversations", sa.Column("last_message_at", sa.DateTime(timezone=True), nullable=True)
    )
    # Backfill from the newest existing message per conversation.
    op.execute(
        "UPDATE conversations SET last_message_at = ("
        "SELECT MAX(m.sent_at) FROM messages m WHERE m.conversation_id = conversations.id"
        ")"
    )


def downgrade() -> None:
    op.drop_column("conversations", "last_message_at")
