"""MessagingService — send + list opaque ciphertext messages (US2).

The ciphertext and envelope are **opaque** to this service: it stores them
verbatim and never parses envelope content (FR-051/SC-002). The only envelope
operation the server performs is a *structural* validation (required
`alg`/`nonce`/`version` fields present and well-typed) recorded as
`integrity_tag_valid_on_receipt=False` — full authenticity is a client-side
concern (FR-027); the server holds no decryption key and cannot verify the tag.

Participant authorization (Constitution §8 RBAC) is enforced here: only an active
participant may send to or list a conversation's messages. Pagination is
cursor-based on `(sent_at, id)` (FR-034), delegated to MessageRepository.
"""

import base64
from datetime import UTC, datetime
from uuid import UUID

from pydantic import ValidationError

from src.models.conversation import ConversationType
from src.models.message import Message
from src.repositories.conversation_repository import ConversationRepository
from src.repositories.identity_key_repository import IdentityKeyRepository
from src.repositories.message_repository import MessageRepository
from src.schemas.messaging import MessageEnvelope, MessageListResponse, MessageResponse
from src.services.messaging_errors import (
    InvalidEnvelopeError,
    InvalidIdentityKeyError,
    NotParticipantError,
)


def _encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def message_to_ws_event(message: Message) -> dict[str, object]:
    """Shape a persisted message as a `message.new` WS event payload — shared by
    the REST send endpoint and the WS-native send handler so both fan-out paths
    serialize identically."""
    return {
        "type": "message.new",
        "data": {
            "conversation_id": str(message.conversation_id),
            "message_id": str(message.id),
            "sender_id": str(message.sender_id),
            "sender_identity_key_id": str(message.sender_identity_key_id),
            "ciphertext": _encode_b64(message.ciphertext),
            "envelope": message.envelope,
            "sent_at": message.sent_at.isoformat(),
        },
    }


def message_to_response(message: Message) -> MessageResponse:
    # Envelope round-trips through MessageEnvelope so the response carries the
    # same structural fields plus any opaque extra crypto material the client put
    # in (extra="allow"). The raw stored dict is the source of truth.
    envelope = MessageEnvelope.model_validate(message.envelope)
    return MessageResponse(
        id=message.id,
        conversation_id=message.conversation_id,
        sender_id=message.sender_id,
        sender_identity_key_id=message.sender_identity_key_id,
        ciphertext=_encode_b64(message.ciphertext),
        envelope=envelope,
        sent_at=message.sent_at,
    )


class MessagingService:
    def __init__(
        self,
        message_repo: MessageRepository,
        conversation_repo: ConversationRepository,
        identity_key_repo: IdentityKeyRepository,
    ) -> None:
        self._messages = message_repo
        self._conversations = conversation_repo
        self._identity_keys = identity_key_repo

    async def _authorize(self, conversation_id: UUID, user_id: UUID) -> None:
        participant = await self._conversations.get_participant(conversation_id, user_id)
        if participant is None or participant.left_at is not None:
            raise NotParticipantError()

    async def send(
        self,
        *,
        sender_id: UUID,
        conversation_id: UUID,
        ciphertext_b64: str,
        envelope: dict[str, object],
        sender_identity_key_id: UUID,
    ) -> tuple[Message, list[UUID]]:
        """Persist one opaque message and return it plus the active participant ids.

        Participant ids are returned (excluding the sender is the caller's job)
        so the router / WebSocket layer can fan `message.new` out without a
        second query.
        """
        await self._authorize(conversation_id, sender_id)

        # The identity key must belong to the sender and be currently active —
        # a rotated-out key is not a valid sender for new messages (it remains
        # valid only for verifying old ones, which is a client concern).
        signing_key = await self._identity_keys.get_by_id(sender_identity_key_id)
        if (
            signing_key is None
            or signing_key.user_id != sender_id
            or signing_key.superseded_at is not None
        ):
            raise InvalidIdentityKeyError()

        # Structural envelope validation only; content stays opaque (FR-051).
        try:
            MessageEnvelope.model_validate(envelope)
        except ValidationError as err:
            raise InvalidEnvelopeError(str(err)) from err

        message = Message(
            conversation_id=conversation_id,
            sender_id=sender_id,
            sender_identity_key_id=sender_identity_key_id,
            ciphertext=base64.b64decode(ciphertext_b64, validate=True),
            envelope=envelope,
            # The server cannot verify the AEAD tag without the key; recorded
            # False, authenticity is the client's job (FR-027).
            integrity_tag_valid_on_receipt=False,
            sent_at=datetime.now(UTC),
        )
        saved = await self._messages.add(message)

        all_participants = await self._conversations.list_all_participants(conversation_id)
        conversation = await self._conversations.get_by_id(conversation_id)
        is_direct = conversation is not None and conversation.type == ConversationType.DIRECT

        if is_direct:
            # FR-055 / FR-057: before fan-out, reactivate any recipient whose
            # membership is left (left_at set) so a previously-deleted chat
            # reappears for them and the `message.new` is delivered to them
            # again — the WhatsApp "deleted chat, then they message you" case.
            # This does NOT apply to group conversations (US3/FR-024/FR-028):
            # a group member's removal is an explicit admin action, and MUST
            # NOT be silently undone by the next message anyone happens to
            # send — including the key-distribution message the remover
            # sends immediately after removing them. Group re-admission goes
            # only through `ConversationService.add_participant`.
            for participant in all_participants:
                if participant.left_at is not None:
                    await self._conversations.mark_reactivated(participant)
            recipient_ids = [p.user_id for p in all_participants]
        else:
            recipient_ids = [p.user_id for p in all_participants if p.left_at is None]

        # FR-058: drive conversation-list ordering + displayed time. The server
        # holds only this timestamp — never a plaintext preview (FR-051).
        await self._conversations.update_last_message_at(conversation_id, saved.sent_at)

        return saved, recipient_ids

    async def list_messages(
        self,
        *,
        requester_id: UUID,
        conversation_id: UUID,
        before_cursor: str | None = None,
        limit: int = 50,
    ) -> MessageListResponse:
        await self._authorize(conversation_id, requester_id)
        messages, next_cursor = await self._messages.list_for_conversation(
            conversation_id, before_cursor=before_cursor, limit=limit
        )
        return MessageListResponse(
            messages=[message_to_response(m) for m in messages],
            next_cursor=next_cursor,
        )
