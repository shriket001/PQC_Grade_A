"""SessionRepository — domain-meaningful data access for Session (FR-006, FR-007)."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from src.models.session import Session
from src.repositories.base import BaseRepository


class SessionRepository(BaseRepository[Session]):
    model = Session

    async def get_by_refresh_token_hash(self, refresh_token_hash: str) -> Session | None:
        result = await self._session.execute(
            select(Session).where(Session.refresh_token_hash == refresh_token_hash)
        )
        return result.scalar_one_or_none()

    async def list_active_for_user(self, user_id: UUID) -> list[Session]:
        result = await self._session.execute(
            select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
        )
        return list(result.scalars().all())

    async def revoke_all_for_user(self, user_id: UUID) -> None:
        sessions = await self.list_active_for_user(user_id)
        now = datetime.now(UTC)
        for session in sessions:
            session.revoked_at = now
        await self._session.flush()

    async def revoke(self, session: Session) -> None:
        """Revoke a single session immediately (FR-004)."""
        if session.revoked_at is None:
            session.revoked_at = datetime.now(UTC)
            await self._session.flush()

    async def rotate_refresh_token(
        self, session: Session, *, new_hash: str, new_expires_at: datetime
    ) -> None:
        """Replace a session's refresh-token hash in place on redemption.

        Rotation (rather than reusing the same refresh token indefinitely)
        means a stolen-and-later-replayed refresh token is detectable: once
        the legitimate client redeems it, the old hash no longer matches
        anything, so a second redemption attempt with the same raw token
        fails as "invalid_refresh_token" instead of silently succeeding.
        """
        session.refresh_token_hash = new_hash
        session.expires_at = new_expires_at
        await self._session.flush()
