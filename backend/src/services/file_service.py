"""FileService — encrypted file/image sharing (US4).

Mirrors `MessagingService`'s stance: `envelope`/ciphertext bytes are opaque to
this service (FR-051/SC-002) — encryption/decryption happens exclusively on
the client. This service only persists ciphertext (in object storage) plus
structural metadata, and gates a share behind participant authorization
(Constitution §8), same as `MessagingService._authorize`.

Every file share creates a companion `Message` row (empty ciphertext, envelope
tagged `kind="file"` plus the new attachment's id) so it sorts into the same
cursor-paginated timeline and WebSocket fan-out as text messages — the
frontend renders it as a file/image bubble instead of text.
"""

from datetime import UTC, datetime
from typing import IO
from uuid import UUID, uuid4

from pydantic import ValidationError

from src.core.config import Settings
from src.models.conversation import ConversationType
from src.models.file_attachment import FileAttachment, FileUploadStatus
from src.models.message import Message
from src.repositories.conversation_repository import ConversationRepository
from src.repositories.file_attachment_repository import FileAttachmentRepository
from src.repositories.file_storage import FileStorage
from src.repositories.identity_key_repository import IdentityKeyRepository
from src.repositories.message_repository import MessageRepository
from src.schemas.messaging import MessageEnvelope
from src.services.file_errors import (
    FileNotFoundError,
    FileNotReadyError,
    FileSizeMismatchError,
    FileTooLargeError,
    FileUploadFailedError,
)
from src.services.messaging_errors import (
    InvalidEnvelopeError,
    InvalidIdentityKeyError,
    NotParticipantError,
)


class _CountingReader:
    """Wraps an uploaded file object, counting bytes actually read so the
    streamed length can be verified against the client's declared size
    without trusting the declaration alone."""

    def __init__(self, fileobj: IO[bytes]) -> None:
        self._fileobj = fileobj
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._fileobj.read(size)
        self.bytes_read += len(chunk)
        return chunk


class FileService:
    def __init__(
        self,
        *,
        file_repo: FileAttachmentRepository,
        message_repo: MessageRepository,
        conversation_repo: ConversationRepository,
        identity_key_repo: IdentityKeyRepository,
        storage: FileStorage,
        settings: Settings,
    ) -> None:
        self._files = file_repo
        self._messages = message_repo
        self._conversations = conversation_repo
        self._identity_keys = identity_key_repo
        self._storage = storage
        self._settings = settings

    async def _authorize(self, conversation_id: UUID, user_id: UUID) -> None:
        participant = await self._conversations.get_participant(conversation_id, user_id)
        if participant is None or participant.left_at is not None:
            raise NotParticipantError()

    async def upload(
        self,
        *,
        conversation_id: UUID,
        sender_id: UUID,
        sender_identity_key_id: UUID,
        file_envelope: dict[str, object],
        content_type: str,
        declared_size_bytes: int,
        fileobj: IO[bytes],
    ) -> tuple[Message, FileAttachment, list[UUID]]:
        await self._authorize(conversation_id, sender_id)

        max_bytes = self._settings.max_file_upload_size_mb * 1024 * 1024
        if declared_size_bytes <= 0 or declared_size_bytes > max_bytes:
            raise FileTooLargeError()

        signing_key = await self._identity_keys.get_by_id(sender_identity_key_id)
        if (
            signing_key is None
            or signing_key.user_id != sender_id
            or signing_key.superseded_at is not None
        ):
            raise InvalidIdentityKeyError()

        try:
            MessageEnvelope.model_validate(file_envelope)
        except ValidationError as err:
            raise InvalidEnvelopeError(str(err)) from err

        attachment_id = uuid4()
        storage_key = f"conversations/{conversation_id}/{attachment_id}"

        counting_reader = _CountingReader(fileobj)
        try:
            await self._storage.put_object(storage_key, counting_reader)  # type: ignore[arg-type]
        except Exception as err:
            raise FileUploadFailedError() from err

        actual_bytes = counting_reader.bytes_read
        if actual_bytes != declared_size_bytes or actual_bytes > max_bytes:
            await self._storage.delete_object(storage_key)
            raise FileSizeMismatchError()

        message_envelope = {
            **file_envelope,
            "kind": "file",
            "file_attachment_id": str(attachment_id),
        }
        message = Message(
            conversation_id=conversation_id,
            sender_id=sender_id,
            sender_identity_key_id=sender_identity_key_id,
            ciphertext=b"",
            envelope=message_envelope,
            integrity_tag_valid_on_receipt=False,
            sent_at=datetime.now(UTC),
        )
        saved_message = await self._messages.add(message)

        attachment = FileAttachment(
            id=attachment_id,
            message_id=saved_message.id,
            storage_key=storage_key,
            envelope=file_envelope,
            content_type=content_type,
            size_bytes=counting_reader.bytes_read,
            upload_status=FileUploadStatus.PENDING,
        )
        saved_attachment = await self._files.add(attachment)
        await self._files.mark_complete(saved_attachment, size_bytes=counting_reader.bytes_read)

        all_participants = await self._conversations.list_all_participants(conversation_id)
        conversation = await self._conversations.get_by_id(conversation_id)
        is_direct = conversation is not None and conversation.type == ConversationType.DIRECT

        if is_direct:
            # Same reactivation semantics as MessagingService.send (FR-055/057)
            # — does not apply to group conversations (FR-024/FR-028).
            for participant in all_participants:
                if participant.left_at is not None:
                    await self._conversations.mark_reactivated(participant)
            recipient_ids = [p.user_id for p in all_participants]
        else:
            recipient_ids = [p.user_id for p in all_participants if p.left_at is None]

        await self._conversations.update_last_message_at(conversation_id, saved_message.sent_at)

        return saved_message, saved_attachment, recipient_ids

    async def download(
        self, *, conversation_id: UUID, file_id: UUID, user_id: UUID
    ) -> tuple[FileAttachment, bytes]:
        await self._authorize(conversation_id, user_id)
        attachment = await self._files.get_by_id(file_id)
        if attachment is None:
            raise FileNotFoundError()
        # Cross-check the attachment's parent message belongs to this
        # conversation — a valid file_id from another conversation must not
        # be downloadable just because the requester is a participant there.
        message = await self._messages.get_by_id(attachment.message_id)
        if message is None or message.conversation_id != conversation_id:
            raise FileNotFoundError()
        if attachment.upload_status != FileUploadStatus.COMPLETE:
            raise FileNotReadyError()
        data = await self._storage.get_object(attachment.storage_key)
        return attachment, data
