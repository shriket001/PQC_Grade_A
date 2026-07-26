"""ConversationRepository — conversation + participant data access (US2).

Phase 5e adds the per-pair + per-user-leave primitives the WhatsApp-style
conversation-list behavior needs: `find_direct` (get-or-create-by-peer-pair,
FR-056), `list_all_participants` (reactivation fan-out needs every membership
row, not just active ones), `mark_left`/`mark_reactivated` (per-user soft
delete/leave + peer-message reactivation, FR-055), `update_last_message_at`
(FR-058 ordering), and `list_for_user` ordered by last activity (newest first).
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import nullslast, select
from sqlalchemy.orm import aliased

from src.models.conversation import (
    Conversation,
    ConversationParticipant,
    ConversationType,
)
from src.repositories.base import BaseRepository


class ConversationRepository(BaseRepository[Conversation]):
    model = Conversation

    async def list_for_user(self, user_id: UUID) -> list[Conversation]:
        """Conversations the user currently participates in (not left), newest
        activity first (FR-058): `last_message_at` desc nulls-last, falling back
        to `created_at` desc for conversations with no messages yet."""
        stmt = (
            select(Conversation)
            .join(
                ConversationParticipant,
                ConversationParticipant.conversation_id == Conversation.id,
            )
            .where(
                ConversationParticipant.user_id == user_id,
                ConversationParticipant.left_at.is_(None),
            )
            .order_by(
                nullslast(Conversation.last_message_at.desc()),
                Conversation.created_at.desc(),
            )
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().unique().all())

    async def find_direct(self, user_a: UUID, user_b: UUID) -> Conversation | None:
        """The existing direct conversation between a pair, regardless of either
        membership's `left_at` (so a left-then-restart pair can be reactivated
        instead of duplicated — FR-056). Returns None when no direct
        conversation between the two users exists.

        With get-or-create-by-peer-pair there is at most one direct conversation
        per pair; `limit(1)` defends against any legacy duplicates.
        """
        pa = aliased(ConversationParticipant)
        pb = aliased(ConversationParticipant)
        stmt = (
            select(Conversation)
            .join(pa, pa.conversation_id == Conversation.id)
            .join(pb, pb.conversation_id == Conversation.id)
            .where(
                Conversation.type == ConversationType.DIRECT,
                pa.user_id == user_a,
                pb.user_id == user_b,
            )
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalars().unique().one_or_none()

    async def get_participant(
        self, conversation_id: UUID, user_id: UUID
    ) -> ConversationParticipant | None:
        result = await self._session.execute(
            select(ConversationParticipant).where(
                ConversationParticipant.conversation_id == conversation_id,
                ConversationParticipant.user_id == user_id,
            )
        )
        return result.scalar_one_or_none()

    async def list_participants(self, conversation_id: UUID) -> list[ConversationParticipant]:
        """Active participants only (left_at is None), oldest membership first."""
        result = await self._session.execute(
            select(ConversationParticipant)
            .where(
                ConversationParticipant.conversation_id == conversation_id,
                ConversationParticipant.left_at.is_(None),
            )
            .order_by(ConversationParticipant.joined_at.asc())
        )
        return list(result.scalars().all())

    async def list_all_participants(self, conversation_id: UUID) -> list[ConversationParticipant]:
        """Every membership row (including left ones). Used on send to reactivate
        left recipients before fan-out (FR-055) and to compute the full recipient
        set."""
        result = await self._session.execute(
            select(ConversationParticipant)
            .where(ConversationParticipant.conversation_id == conversation_id)
            .order_by(ConversationParticipant.joined_at.asc())
        )
        return list(result.scalars().all())

    async def add_participant(
        self, participant: ConversationParticipant
    ) -> ConversationParticipant:
        self._session.add(participant)
        await self._session.flush()
        return participant

    async def mark_left(self, participant: ConversationParticipant) -> None:
        """Per-user soft delete (leave): stamp the caller's `left_at` (FR-055).
        The conversation, the other participant's membership, and all messages
        are left intact — no cascade."""
        if participant.left_at is None:
            participant.left_at = datetime.now(UTC)
            await self._session.flush()

    async def mark_reactivated(self, participant: ConversationParticipant) -> None:
        """Clear a left membership so the conversation reappears for that user
        (FR-055): called when the peer sends a message into a conversation the
        user had left, or when a user re-starts a left direct conversation
        (FR-056)."""
        if participant.left_at is not None:
            participant.left_at = None
            await self._session.flush()

    async def update_last_message_at(self, conversation_id: UUID, sent_at: datetime) -> None:
        """Drive conversation-list ordering + displayed time (FR-058). Called on
        every send. The server holds only this timestamp — never a plaintext
        preview (FR-051)."""
        conversation = await self.get_by_id(conversation_id)
        if conversation is not None and (
            conversation.last_message_at is None or sent_at > conversation.last_message_at
        ):
            conversation.last_message_at = sent_at
            await self._session.flush()
