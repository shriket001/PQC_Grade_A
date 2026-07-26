"""file attachments

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-24 00:00:00.000000

Adds `file_attachments`: one row per shared file/image, one-to-one with a
companion `Message` row (US4). The object in MinIO/S3 at `storage_key` holds
only client-side-encrypted ciphertext; `envelope` carries the file cipher's
algorithm-agnostic metadata (alg/nonce/version), opaque to the backend
(FR-051/SC-002). `upload_status` gates downloadability so a partially
uploaded file is never addressable (FR-040).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "file_attachments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "message_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("messages.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("storage_key", sa.String(length=512), nullable=False),
        sa.Column("envelope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("content_type", sa.String(length=255), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column(
            "upload_status",
            sa.Enum("pending", "complete", "failed", name="file_upload_status"),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_file_attachments_message_id",
        "file_attachments",
        ["message_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_file_attachments_message_id", table_name="file_attachments")
    op.drop_table("file_attachments")
    op.execute("DROP TYPE IF EXISTS file_upload_status")
