"""MfaFactorRepository — domain-meaningful data access for MfaFactor (FR-009)."""

from uuid import UUID

from sqlalchemy import select

from src.models.mfa_factor import MfaFactor
from src.repositories.base import BaseRepository


class MfaFactorRepository(BaseRepository[MfaFactor]):
    model = MfaFactor

    async def get_active_for_user(self, user_id: UUID) -> MfaFactor | None:
        result = await self._session.execute(
            select(MfaFactor).where(
                MfaFactor.user_id == user_id,
                MfaFactor.enabled_at.is_not(None),
                MfaFactor.disabled_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def get_pending_for_user(self, user_id: UUID) -> MfaFactor | None:
        result = await self._session.execute(
            select(MfaFactor).where(
                MfaFactor.user_id == user_id,
                MfaFactor.enabled_at.is_(None),
                MfaFactor.disabled_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def save(self, entity: MfaFactor) -> None:
        """Flush an in-place mutation (e.g. setting `enabled_at`/`disabled_at`)."""
        await self._session.flush()
