"""wrapped identity keys

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-22 04:00:00.000000

Adds optional password-wrapped private-key columns to `identity_keys` (FR-054:
cross-device recoverable identity). The wrapped blobs + wrap parameters are
opaque to the server — it stores and relays them but never decrypts. All columns
are nullable: legacy rows and the public-directory view carry none, so no
backfill is required.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "identity_keys",
        sa.Column("wrapped_signing_private_key", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "identity_keys",
        sa.Column("wrapped_kem_private_key", sa.LargeBinary(), nullable=True),
    )
    op.add_column("identity_keys", sa.Column("wrap_nonce", sa.LargeBinary(), nullable=True))
    op.add_column("identity_keys", sa.Column("wrap_kdf_salt", sa.LargeBinary(), nullable=True))
    op.add_column(
        "identity_keys", sa.Column("wrap_kdf_params", sa.String(length=64), nullable=True)
    )
    op.add_column("identity_keys", sa.Column("wrap_alg", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column("identity_keys", "wrap_alg")
    op.drop_column("identity_keys", "wrap_kdf_params")
    op.drop_column("identity_keys", "wrap_kdf_salt")
    op.drop_column("identity_keys", "wrap_nonce")
    op.drop_column("identity_keys", "wrapped_kem_private_key")
    op.drop_column("identity_keys", "wrapped_signing_private_key")
