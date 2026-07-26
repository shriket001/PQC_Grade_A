"""FileAttachment model (US4).

An encrypted file/image shared in a conversation. Every attachment has exactly
one companion `Message` row (the timeline entry the attachment renders under,
client-side, as a file/image bubble) — `message_id` is unique so the
relationship is one-to-one. `storage_key`/`envelope`/actual bytes are opaque
ciphertext to the backend, mirroring `Message.ciphertext`/`envelope`
(FR-051/SC-002): the object in MinIO/S3 holds only ciphertext, and only the
client can decrypt it. `content_type`/`size_bytes` are declared metadata, not
security-authoritative (data-model.md). `upload_status` prevents a
partially-uploaded object from ever being addressable/downloadable (FR-040) —
it starts `pending`, and only a fully-streamed, size-verified upload is
promoted to `complete`; anything else is left/marked `failed` and never
served.
"""

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.message import Message


class FileUploadStatus(enum.StrEnum):
    PENDING = "pending"
    COMPLETE = "complete"
    FAILED = "failed"


class FileAttachment(Base):
    __tablename__ = "file_attachments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("messages.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    # Object-storage key/path (research.md #4); the object itself holds only
    # ciphertext produced client-side.
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)
    # Algorithm-agnostic envelope for the file cipher: {alg, nonce, version}.
    envelope: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    # Declared MIME type (not trusted for security decisions beyond size/type
    # gating, which itself happens client-side per FR-051 — the server can't
    # see plaintext to sniff it).
    content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    # Declared size, cross-checked against the actual streamed length at
    # upload time (FR-039).
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    upload_status: Mapped[FileUploadStatus] = mapped_column(
        Enum(
            FileUploadStatus,
            name="file_upload_status",
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
        default=FileUploadStatus.PENDING,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    message: Mapped["Message"] = relationship(back_populates="file_attachment")
