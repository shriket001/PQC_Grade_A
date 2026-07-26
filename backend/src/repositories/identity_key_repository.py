"""IdentityKeyRepository — public-key directory data access (US2, FR-043/FR-044/FR-049).

Stores public key material only; private keys never reach the server. Rotation
(FR-049) is handled at the service layer, which calls `mark_superseded` on the
outgoing record and `add` on the new one in one transaction.
"""

from uuid import UUID

from sqlalchemy import select

from src.models.identity_key import IdentityKeyRecord
from src.repositories.base import BaseRepository


class IdentityKeyRepository(BaseRepository[IdentityKeyRecord]):
    model = IdentityKeyRecord

    async def list_active_for_user(self, user_id: UUID) -> list[IdentityKeyRecord]:
        """Active (non-superseded) keys for a user, newest key_version first."""
        result = await self._session.execute(
            select(IdentityKeyRecord)
            .where(IdentityKeyRecord.user_id == user_id, IdentityKeyRecord.superseded_at.is_(None))
            .order_by(IdentityKeyRecord.key_version.desc())
        )
        return list(result.scalars().all())

    async def get_active_for_user(
        self, user_id: UUID, *, key_version: int | None = None
    ) -> IdentityKeyRecord | None:
        """The user's current active key, or the one matching a specific version."""
        stmt = select(IdentityKeyRecord).where(
            IdentityKeyRecord.user_id == user_id, IdentityKeyRecord.superseded_at.is_(None)
        )
        if key_version is not None:
            stmt = stmt.where(IdentityKeyRecord.key_version == key_version)
        else:
            stmt = stmt.order_by(IdentityKeyRecord.key_version.desc()).limit(1)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def mark_superseded(self, key: IdentityKeyRecord) -> None:
        """Mark an existing key as rotated out (retained for verifiability)."""
        from datetime import UTC, datetime

        if key.superseded_at is None:
            key.superseded_at = datetime.now(UTC)
            await self._session.flush()
