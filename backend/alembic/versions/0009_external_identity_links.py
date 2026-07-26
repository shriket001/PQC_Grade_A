"""external identity links

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-26 00:00:00.000000

Adds `external_identity_links`: links a local User to an external OIDC/SAML
identity provider's subject (FR-010/FR-011 inbound directions). Used first by
the Google OIDC Relying Party login — `provider_identifier` is the IdP's
issuer (e.g. Google's `https://accounts.google.com`), `subject` its stable
subject id for the user (never the email, which can change).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "external_identity_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("provider_identifier", sa.String(length=512), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_external_identity_links_user_id", "external_identity_links", ["user_id"]
    )
    op.create_unique_constraint(
        "uq_external_identity_links_protocol_provider_subject",
        "external_identity_links",
        ["protocol", "provider_identifier", "subject"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_external_identity_links_protocol_provider_subject",
        "external_identity_links",
        type_="unique",
    )
    op.drop_index("ix_external_identity_links_user_id", table_name="external_identity_links")
    op.drop_table("external_identity_links")
