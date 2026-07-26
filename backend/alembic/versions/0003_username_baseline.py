"""username baseline

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-22 02:00:00.000000

Adds the unique `username` handle to `users` (FR-052/FR-053): the public
identifier users start conversations and are discovered by. Existing rows are
backfilled from the email local-part (lowercased + sanitized to the username
charset, truncated to fit the column, with a short id-derived suffix on
collision) so already-registered accounts — including the seeded admin and any
self-registered dev users — become discoverable by username without being asked
to re-register.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add the column nullable so existing rows don't violate NOT NULL.
    op.add_column("users", sa.Column("username", sa.String(length=32), nullable=True))

    # 2. Backfill: derive a username from the email local-part, lowercased and
    #    sanitized to [a-z0-9_], truncated to 25 chars so a later collision
    #    suffix ('_' + 6 hex) still fits the 32-char column.
    op.execute("""
        UPDATE users
        SET username = left(
            lower(regexp_replace(split_part(email, '@', 1), '[^a-z0-9_]', '_', 'g')),
            25
        )
        WHERE username IS NULL
        """)

    # 3. Resolve any collisions by suffixing the later-id row with 6 hex chars
    #    derived from its id, guaranteeing the unique index can be created.
    op.execute("""
        UPDATE users u
        SET username = u.username || '_' || substr(md5(u.id::text), 1, 6)
        WHERE u.username IS NOT NULL
          AND EXISTS (
            SELECT 1 FROM users x
            WHERE x.username = u.username AND x.id < u.id
          )
        """)

    # 4. Tighten to NOT NULL and add the unique index (case-insensitivity is
    #    enforced at the application layer by normalizing to lowercase).
    op.alter_column("users", "username", nullable=False)
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_username", table_name="users")
    op.drop_column("users", "username")
