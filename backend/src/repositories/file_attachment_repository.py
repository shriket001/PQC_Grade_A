"""FileAttachmentRepository — opaque file-attachment data access (US4).

`storage_key`/`envelope` are opaque to this repository, mirroring
MessageRepository's stance on ciphertext/envelope (FR-051/SC-002).
"""

from uuid import UUID

from sqlalchemy import select

from src.models.file_attachment import FileAttachment, FileUploadStatus
from src.repositories.base import BaseRepository


class FileAttachmentRepository(BaseRepository[FileAttachment]):
    model = FileAttachment

    async def get_by_message_id(self, message_id: UUID) -> FileAttachment | None:
        result = await self._session.execute(
            select(FileAttachment).where(FileAttachment.message_id == message_id)
        )
        return result.scalar_one_or_none()

    async def mark_complete(self, attachment: FileAttachment, *, size_bytes: int) -> FileAttachment:
        attachment.upload_status = FileUploadStatus.COMPLETE
        attachment.size_bytes = size_bytes
        await self._session.flush()
        return attachment

    async def mark_failed(self, attachment: FileAttachment) -> FileAttachment:
        attachment.upload_status = FileUploadStatus.FAILED
        await self._session.flush()
        return attachment
