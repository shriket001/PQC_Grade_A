"""ConversationKeyBackupRepository — opaque per-user conversation-key backup
data access. Wrapped key material is never parsed here (mirrors
MessageRepository's opaque-ciphertext stance)."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from src.models.conversation_key_backup import ConversationKeyBackup
from src.repositories.base import BaseRepository


class ConversationKeyBackupRepository(BaseRepository[ConversationKeyBackup]):
    model = ConversationKeyBackup

    async def get_for_user(
        self, conversation_id: UUID, user_id: UUID
    ) -> ConversationKeyBackup | None:
        result = await self._session.execute(
            select(ConversationKeyBackup).where(
                ConversationKeyBackup.conversation_id == conversation_id,
                ConversationKeyBackup.user_id == user_id,
            )
        )
        return result.scalar_one_or_none()

    async def upsert(
        self,
        *,
        conversation_id: UUID,
        user_id: UUID,
        wrapped_key: bytes,
        wrap_nonce: bytes,
        wrap_kdf_salt: bytes,
        wrap_kdf_params: str,
        wrap_alg: str,
    ) -> ConversationKeyBackup:
        """Store (or overwrite) the caller's wrapped key backup for a
        conversation. One row per (conversation, user) — a re-push (e.g. after
        the protocol's self-healing re-key) replaces the prior backup."""
        existing = await self.get_for_user(conversation_id, user_id)
        if existing is not None:
            existing.wrapped_key = wrapped_key
            existing.wrap_nonce = wrap_nonce
            existing.wrap_kdf_salt = wrap_kdf_salt
            existing.wrap_kdf_params = wrap_kdf_params
            existing.wrap_alg = wrap_alg
            existing.updated_at = datetime.now(UTC)
            await self._session.flush()
            return existing
        record = ConversationKeyBackup(
            conversation_id=conversation_id,
            user_id=user_id,
            wrapped_key=wrapped_key,
            wrap_nonce=wrap_nonce,
            wrap_kdf_salt=wrap_kdf_salt,
            wrap_kdf_params=wrap_kdf_params,
            wrap_alg=wrap_alg,
        )
        return await self.add(record)
