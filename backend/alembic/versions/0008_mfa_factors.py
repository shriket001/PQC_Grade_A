"""mfa factors

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-24 00:00:00.000000

Adds `mfa_factors`: a user's registered TOTP second factor (FR-009). The
secret is stored encrypted at rest (`secret_ciphertext`/`secret_nonce`, via
the backend crypto module) rather than hashed, since a TOTP secret must stay
reversible to compute codes. Rows are never deleted — `enabled_at`/
`disabled_at` track pending/active/disabled history for audit purposes.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mfa_factors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("type", sa.String(length=32), nullable=False, server_default="totp"),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("secret_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_mfa_factors_user_id", "mfa_factors", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_mfa_factors_user_id", table_name="mfa_factors")
    op.drop_table("mfa_factors")
