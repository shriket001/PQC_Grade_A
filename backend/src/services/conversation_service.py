"""ConversationService — conversation lifecycle + participant authz (US2/US3).

Participant authorization (Constitution §8 RBAC) is enforced here at the service
layer — a router never decides on its own whether a user may read a
conversation; it calls `authorize_participant` / `_authorize_group_admin`.

Phase 5e changes the *direct*-conversation lifecycle to WhatsApp-style behavior:
- `create_direct` is **get-or-create-by-peer-pair** (FR-056): an existing direct
  conversation between the creator and the named peer is reused (never
  duplicated), and if the creator had previously left it (FR-055) their
  membership is reactivated instead of creating a new conversation.
- `delete_conversation` **hard-deletes** a direct conversation (its messages and
  both participants' memberships, via cascade) so re-adding the same peer
  starts over with a brand-new conversation id and a fresh key exchange. Group
  conversations still use the per-user soft delete (leave) (FR-055): only the
  caller's `left_at` is stamped, and a peer's later message reactivates a left
  membership (handled in `MessagingService.send`).

Phase 5 (US3) adds *group* conversations (FR-024):
- `create_group` makes the creator `group_admin`; every other id joins as
  `member`.
- `add_participant`/`remove_participant` are group_admin-only (self-removal
  is also allowed — a member may always leave). Removal sets `left_at`, the
  same field US2 uses for per-user leave, which bounds the removed member's
  *server-side* access going forward (`MessagingService._authorize`).
- **FR-028's actual enforcement is at the crypto layer, not here**: the server
  keeps returning full message history to any currently-active participant
  (unchanged `MessagingService.list_messages` — no per-window filtering), but
  the frontend's group-key epoch distribution (`groupKeyManager.ts`) never
  sends a removed member — or a newly-added one — the group key for any epoch
  they were not an active member during. A removed-then-rejoined member can
  read messages from the point of rejoining onward, not the gap in between,
  because they only ever receive the *current* epoch's key. This mirrors
  Decision #1 (research.md): content readability is a function of who holds
  which decryption key, never a server-side authorization decision over
  ciphertext the server can't read anyway.
"""

from uuid import UUID

from src.models.conversation import (
    Conversation,
    ConversationParticipant,
    ConversationType,
    ParticipantRole,
)
from src.repositories.conversation_repository import ConversationRepository
from src.services.messaging_errors import (
    ConversationNotFoundError,
    ConversationTypeMismatchError,
    InvalidConversationRequestError,
    NotGroupAdminError,
    NotParticipantError,
    ParticipantAlreadyActiveError,
)


class ConversationService:
    def __init__(self, conversation_repo: ConversationRepository) -> None:
        self._repo = conversation_repo

    async def create_direct(
        self,
        *,
        creator_id: UUID,
        participant_user_ids: list[UUID],
        name: str | None = None,
    ) -> Conversation:
        """Get-or-create a 2-participant direct conversation (FR-056).

        The request DTO already constrains `participant_user_ids` to exactly one
        id; this service additionally rejects a self-conversation (creator ==
        the other participant). If a direct conversation between the creator and
        the named peer already exists, it is reused — and if the creator had
        previously left it (FR-055), the creator's membership is reactivated
        (`left_at` cleared) and that conversation is returned. Only when no such
        conversation exists is a new one created. This is enforced server-side
        so two clients starting the same pair concurrently cannot produce two
        direct conversations between the same two users.
        """
        if len(participant_user_ids) != 1:
            raise InvalidConversationRequestError(
                "direct conversation requires one other participant"
            )
        other_id = participant_user_ids[0]
        if other_id == creator_id:
            raise InvalidConversationRequestError("cannot create a conversation with yourself")

        existing = await self._repo.find_direct(creator_id, other_id)
        if existing is not None:
            # Reuse the existing direct conversation; reactivate the creator's
            # membership if they had left it (FR-055/FR-056). The peer's
            # membership is left as-is — if the peer had left, a subsequent
            # message reactivates them (MessagingService.send).
            creator_membership = await self._repo.get_participant(existing.id, creator_id)
            if creator_membership is not None:
                await self.reactivate_participant(existing.id, creator_id)
            return existing

        conversation = Conversation(
            type=ConversationType.DIRECT,
            name=name,
            created_by=creator_id,
        )
        await self._repo.add(conversation)
        # Both participants join at creation; direct conversations have no admin.
        await self._repo.add_participant(
            ConversationParticipant(conversation_id=conversation.id, user_id=creator_id)
        )
        await self._repo.add_participant(
            ConversationParticipant(conversation_id=conversation.id, user_id=other_id)
        )
        return conversation

    async def create_group(
        self,
        *,
        creator_id: UUID,
        participant_user_ids: list[UUID],
        name: str,
    ) -> Conversation:
        """Create a group conversation (FR-024). The creator becomes
        `group_admin`; every other id becomes a `member`. Duplicate ids and
        the creator's own id (if present in the list) are silently
        deduplicated rather than rejected — the caller has already resolved
        usernames to ids independently and a duplicate isn't a meaningful
        client error."""
        other_ids = [uid for uid in dict.fromkeys(participant_user_ids) if uid != creator_id]
        if not other_ids:
            raise InvalidConversationRequestError(
                "a group requires at least one participant besides the creator"
            )
        conversation = Conversation(type=ConversationType.GROUP, name=name, created_by=creator_id)
        await self._repo.add(conversation)
        await self._repo.add_participant(
            ConversationParticipant(
                conversation_id=conversation.id,
                user_id=creator_id,
                role=ParticipantRole.GROUP_ADMIN,
            )
        )
        for uid in other_ids:
            await self._repo.add_participant(
                ConversationParticipant(
                    conversation_id=conversation.id, user_id=uid, role=ParticipantRole.MEMBER
                )
            )
        return conversation

    async def add_participant(
        self, *, conversation_id: UUID, actor_id: UUID, target_user_id: UUID
    ) -> ConversationParticipant:
        """Add a member to a group conversation (FR-024) — group_admin only.

        Re-adding a previously-removed member reactivates their existing row
        (clears `left_at`) rather than duplicating it; adding a currently
        active member is rejected (409)."""
        conversation = await self._repo.get_by_id(conversation_id)
        if conversation is None:
            raise ConversationNotFoundError()
        if conversation.type != ConversationType.GROUP:
            raise ConversationTypeMismatchError(
                "participants can only be managed on a group conversation"
            )
        await self._authorize_group_admin(conversation_id, actor_id)

        existing = await self._repo.get_participant(conversation_id, target_user_id)
        if existing is not None:
            if existing.left_at is None:
                raise ParticipantAlreadyActiveError()
            await self._repo.mark_reactivated(existing)
            return existing
        return await self._repo.add_participant(
            ConversationParticipant(
                conversation_id=conversation_id,
                user_id=target_user_id,
                role=ParticipantRole.MEMBER,
            )
        )

    async def remove_participant(
        self, *, conversation_id: UUID, actor_id: UUID, target_user_id: UUID
    ) -> None:
        """Remove a member from a group conversation, or let a member leave
        themselves (FR-024/FR-028). Only a group_admin may remove someone
        else; any active member may remove (leave) themselves. Sets
        `left_at` on the target's membership — see the module docstring for
        why that alone does not need to gate server-side message reads."""
        conversation = await self._repo.get_by_id(conversation_id)
        if conversation is None:
            raise ConversationNotFoundError()
        if conversation.type != ConversationType.GROUP:
            raise ConversationTypeMismatchError(
                "participants can only be managed on a group conversation"
            )
        target = await self._repo.get_participant(conversation_id, target_user_id)
        if target is None or target.left_at is not None:
            raise NotParticipantError()
        if actor_id != target_user_id:
            await self._authorize_group_admin(conversation_id, actor_id)
        await self._repo.mark_left(target)

    async def _authorize_group_admin(
        self, conversation_id: UUID, user_id: UUID
    ) -> ConversationParticipant:
        participant = await self._repo.get_participant(conversation_id, user_id)
        if (
            participant is None
            or participant.left_at is not None
            or participant.role != ParticipantRole.GROUP_ADMIN
        ):
            raise NotGroupAdminError()
        return participant

    async def list_for_user(self, user_id: UUID) -> list[Conversation]:
        return await self._repo.list_for_user(user_id)

    async def delete_conversation(self, *, requester_id: UUID, conversation_id: UUID) -> None:
        """Delete a conversation.

        Direct conversations are **hard-deleted**: the conversation row, both
        participants' memberships, and every message are removed (cascade via
        the ORM relationship). Re-adding the same contact afterwards therefore
        creates a brand-new conversation with a fresh id — no stale history
        reappears, and the client-side per-conversation key (keyed by
        conversation id) is naturally orphaned, forcing a brand-new ML-KEM-768
        key exchange rather than reusing/colliding with a previous one.

        Group conversations keep the previous per-user soft-delete (leave)
        behavior: only the caller's `left_at` is stamped, since a hard delete
        would destroy the conversation for every other member too.

        Authorization (Constitution §8 RBAC) is enforced here: only an *active*
        participant may leave/delete. 404 if the conversation does not exist;
        403 `not_participant` if the caller is not an active participant.
        """
        conversation = await self._repo.get_by_id(conversation_id)
        if conversation is None:
            raise ConversationNotFoundError()
        participant = await self.authorize_participant(conversation_id, requester_id)
        if conversation.type == ConversationType.DIRECT:
            await self._repo.delete(conversation)
        else:
            await self._repo.mark_left(participant)

    async def reactivate_participant(self, conversation_id: UUID, user_id: UUID) -> None:
        """Clear a user's `left_at` on a conversation so it reappears in their
        list (FR-055/FR-056). No-op if the membership is already active or absent.
        """
        participant = await self._repo.get_participant(conversation_id, user_id)
        if participant is not None:
            await self._repo.mark_reactivated(participant)

    async def get_participant(
        self, conversation_id: UUID, user_id: UUID
    ) -> ConversationParticipant | None:
        return await self._repo.get_participant(conversation_id, user_id)

    async def list_participants(self, conversation_id: UUID) -> list[ConversationParticipant]:
        return await self._repo.list_participants(conversation_id)

    async def list_participants_with_users(
        self, conversation_id: UUID
    ) -> list[tuple[ConversationParticipant, str, str]]:
        """Active participants joined with their public username + display_name,
        so the conversation response can carry labels directly (no per-peer
        `GET /users/{id}` round-trip on the client)."""
        return await self._repo.list_participants_with_users(conversation_id)

    async def authorize_participant(
        self, conversation_id: UUID, user_id: UUID
    ) -> ConversationParticipant:
        """Return the active membership row, or raise NotParticipantError.

        A left participant is treated as not-a-participant for authorization:
        historical readability (a left member reading old messages) is a US3
        concern and is gated on membership windows there, not here. A left user
        regains access by re-starting the conversation (FR-056 reactivates them)
        or by being reactivated when the peer sends (FR-055).
        """
        participant = await self._repo.get_participant(conversation_id, user_id)
        if participant is None or participant.left_at is not None:
            raise NotParticipantError()
        return participant
