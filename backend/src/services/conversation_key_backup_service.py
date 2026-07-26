"""ConversationKeyBackupService — password-recoverable per-conversation message
key backup (extends FR-054's identity-key recovery to the 1:1 conversation
symmetric key; see `ConversationKeyBackup`).

The wrapped key blob is opaque to this service — it never decrypts it. Only
current active participants may push/pull their own backup for a conversation.
"""

from uuid import UUID

from src.models.conversation_key_backup import ConversationKeyBackup
from src.repositories.conversation_key_backup_repository import ConversationKeyBackupRepository
from src.repositories.conversation_repository import ConversationRepository
from src.services.messaging_errors import ConversationNotFoundError, NotParticipantError


class ConversationKeyBackupService:
    def __init__(
        self,
        backup_repo: ConversationKeyBackupRepository,
        conversation_repo: ConversationRepository,
    ) -> None:
        self._backups = backup_repo
        self._conversations = conversation_repo

    async def _authorize(self, conversation_id: UUID, user_id: UUID) -> None:
        conversation = await self._conversations.get_by_id(conversation_id)
        if conversation is None:
            raise ConversationNotFoundError()
        participant = await self._conversations.get_participant(conversation_id, user_id)
        if participant is None or participant.left_at is not None:
            raise NotParticipantError()

    async def put(
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
        await self._authorize(conversation_id, user_id)
        return await self._backups.upsert(
            conversation_id=conversation_id,
            user_id=user_id,
            wrapped_key=wrapped_key,
            wrap_nonce=wrap_nonce,
            wrap_kdf_salt=wrap_kdf_salt,
            wrap_kdf_params=wrap_kdf_params,
            wrap_alg=wrap_alg,
        )

    async def get(self, *, conversation_id: UUID, user_id: UUID) -> ConversationKeyBackup | None:
        await self._authorize(conversation_id, user_id)
        return await self._backups.get_for_user(conversation_id, user_id)
