"""Conversation + ConversationParticipant models (US2).

A direct (2-participant) or group (N-participant) messaging context. Membership
windows (`joined_at`/`left_at`) govern historical readability (Story 3); for US2
(direct only) membership is fixed at creation.
"""

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.message import Message
    from src.models.user import User


class ConversationType(enum.StrEnum):
    DIRECT = "direct"
    GROUP = "group"


class ParticipantRole(enum.StrEnum):
    MEMBER = "member"
    GROUP_ADMIN = "group_admin"


class Conversation(Base):
    __tablename__ = "conversations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type: Mapped[ConversationType] = mapped_column(
        Enum(ConversationType, name="conversation_type"), nullable=False
    )
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    # FR-058: drives conversation-list ordering (newest first) + the displayed
    # time. The server holds ONLY this timestamp — the latest-message *preview*
    # is decrypted client-side (FR-051). Updated on every send; nullable for
    # conversations with no messages yet (list falls back to created_at).
    last_message_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    participants: Mapped[list["ConversationParticipant"]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan"
    )
    messages: Mapped[list["Message"]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan"
    )


class ConversationParticipant(Base):
    __tablename__ = "conversation_participants"
    __table_args__ = (
        # A user has at most one membership row per conversation (re-join after
        # leave is a US3 concern; for US2 direct conversations this is invariant).
        UniqueConstraint("conversation_id", "user_id", name="uq_conversation_participant"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[ParticipantRole | None] = mapped_column(
        Enum(ParticipantRole, name="participant_role"), nullable=True
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    left_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    conversation: Mapped["Conversation"] = relationship(back_populates="participants")
    user: Mapped["User"] = relationship()
