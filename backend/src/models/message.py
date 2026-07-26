"""Message + MessageReadReceipt models (US2).

A single ciphertext unit of communication. `ciphertext` + `envelope` are
**opaque** to the backend — no code path parses them for content (research.md
#1, FR-051/SC-002); the server only validates envelope *structure* at ingest
and stores the rest verbatim. Pagination is cursor-based on `(sent_at, id)`
(FR-034).
"""

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, LargeBinary
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.conversation import Conversation
    from src.models.file_attachment import FileAttachment
    from src.models.identity_key import IdentityKeyRecord


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        # Cursor pagination index: chronological ordering by sent_at, with id as
        # the tiebreaker for equal timestamps (FR-034).
        Index("ix_messages_sent_at_id", "sent_at", "id"),
        Index("ix_messages_conversation_sent_at", "conversation_id", "sent_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sender_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # Which identity key signed/encrypted this message (FR-027).
    sender_identity_key_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity_keys.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    # AES-256-GCM ciphertext (Grade A); never inspected by the backend.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Algorithm-agnostic envelope: {alg, nonce, version, ...crypto material...}.
    # Stored as JSONB; only the structural fields are validated at ingest.
    envelope: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    # Recorded at ingest from a cheap *structural* envelope check; full
    # authenticity is a client-side concern (FR-027).
    integrity_tag_valid_on_receipt: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    conversation: Mapped["Conversation"] = relationship(back_populates="messages")
    sender_identity_key: Mapped["IdentityKeyRecord"] = relationship(back_populates="messages")
    read_receipts: Mapped[list["MessageReadReceipt"]] = relationship(
        back_populates="message", cascade="all, delete-orphan"
    )
    file_attachment: Mapped["FileAttachment | None"] = relationship(
        back_populates="message", cascade="all, delete-orphan", uselist=False
    )


class MessageReadReceipt(Base):
    """Per-recipient read timestamps (FR-030). Modeled as a child table for
    multi-participant group correctness; the US2 read-receipt endpoint is a
    documented limitation (lands with the read-receipt work)."""

    __tablename__ = "message_read_receipts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("messages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    read_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    message: Mapped["Message"] = relationship(back_populates="read_receipts")
