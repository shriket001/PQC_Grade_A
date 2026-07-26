"""messaging baseline

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-22 01:00:00.000000

US2: identity key directory + conversations + participants + messages + read
receipts. Ciphertext and envelope are opaque to the backend (FR-051/SC-002).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "identity_keys",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("device_label", sa.String(length=100), nullable=False),
        sa.Column("public_signing_key", sa.LargeBinary(), nullable=False),
        sa.Column("public_kem_key", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("rotation_attestation", sa.LargeBinary(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_identity_keys_user_id", "identity_keys", ["user_id"], unique=False)

    op.create_table(
        "conversations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "type",
            sa.Enum("DIRECT", "GROUP", name="conversation_type"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=200), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "conversation_participants",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("conversation_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column(
            "role",
            sa.Enum("MEMBER", "GROUP_ADMIN", name="participant_role"),
            nullable=True,
        ),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("left_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("conversation_id", "user_id", name="uq_conversation_participant"),
    )
    op.create_index(
        "ix_conversation_participants_conversation_id",
        "conversation_participants",
        ["conversation_id"],
        unique=False,
    )
    op.create_index(
        "ix_conversation_participants_user_id",
        "conversation_participants",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "messages",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("conversation_id", sa.UUID(), nullable=False),
        sa.Column("sender_id", sa.UUID(), nullable=False),
        sa.Column("sender_identity_key_id", sa.UUID(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("envelope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "integrity_tag_valid_on_receipt",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["sender_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["sender_identity_key_id"], ["identity_keys.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_messages_conversation_id", "messages", ["conversation_id"], unique=False)
    op.create_index(
        "ix_messages_sender_identity_key_id",
        "messages",
        ["sender_identity_key_id"],
        unique=False,
    )
    op.create_index("ix_messages_sent_at_id", "messages", ["sent_at", "id"], unique=False)
    op.create_index(
        "ix_messages_conversation_sent_at",
        "messages",
        ["conversation_id", "sent_at"],
        unique=False,
    )

    op.create_table(
        "message_read_receipts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("message_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_message_read_receipts_message_id",
        "message_read_receipts",
        ["message_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_message_read_receipts_message_id", table_name="message_read_receipts")
    op.drop_table("message_read_receipts")

    op.drop_index("ix_messages_conversation_sent_at", table_name="messages")
    op.drop_index("ix_messages_sent_at_id", table_name="messages")
    op.drop_index("ix_messages_sender_identity_key_id", table_name="messages")
    op.drop_index("ix_messages_conversation_id", table_name="messages")
    op.drop_table("messages")

    op.drop_index("ix_conversation_participants_user_id", table_name="conversation_participants")
    op.drop_index(
        "ix_conversation_participants_conversation_id", table_name="conversation_participants"
    )
    op.drop_table("conversation_participants")

    op.drop_table("conversations")
    op.execute("DROP TYPE IF EXISTS participant_role")
    op.execute("DROP TYPE IF EXISTS conversation_type")

    op.drop_index("ix_identity_keys_user_id", table_name="identity_keys")
    op.drop_table("identity_keys")
