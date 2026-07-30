"""Conversation endpoints — create/list direct + group conversations (US2/US3).

All bodies are strict Pydantic DTOs (Constitution Principle VII). Authorization
(participant-only / group_admin-only access) is delegated to
ConversationService, which enforces RBAC at the service layer (Constitution §8).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response

from src.api.ws.connection_manager import connection_manager
from src.core.dependencies import (
    AuthContext,
    get_conversation_service,
    get_current_session,
    get_user_repository,
)
from src.models.conversation import Conversation, ConversationParticipant
from src.repositories.user_repository import UserRepository
from src.schemas.messaging import (
    AddParticipantRequest,
    ConversationParticipantResponse,
    ConversationResponse,
    CreateConversationRequest,
)
from src.services.conversation_service import ConversationService

router = APIRouter()


def _participant_to_response(
    p: ConversationParticipant,
    *,
    username: str | None = None,
    display_name: str | None = None,
) -> ConversationParticipantResponse:
    return ConversationParticipantResponse(
        user_id=p.user_id,
        role=p.role.value if p.role is not None else None,
        joined_at=p.joined_at,
        username=username,
        display_name=display_name,
    )


async def _to_response(
    service: ConversationService, conversation: Conversation
) -> ConversationResponse:
    # Joined with the users table so each participant carries its public
    # username + display_name — the client renders labels immediately instead
    # of firing a per-peer GET /users/{id} (which flashed a truncated id while
    # the in-memory name map was empty on refresh).
    participants = await service.list_participants_with_users(conversation.id)
    return ConversationResponse(
        id=conversation.id,
        type=conversation.type.value,
        name=conversation.name,
        created_by=conversation.created_by,
        created_at=conversation.created_at,
        last_message_at=conversation.last_message_at,
        participants=[
            _participant_to_response(p, username=username, display_name=display_name)
            for p, username, display_name in participants
        ],
    )


@router.post("/conversations", response_model=ConversationResponse, status_code=201)
async def create_conversation(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    body: CreateConversationRequest,
    service: Annotated[ConversationService, Depends(get_conversation_service)],
) -> ConversationResponse:
    if body.type == "group":
        conversation = await service.create_group(
            creator_id=ctx.user.id,
            participant_user_ids=body.participant_user_ids,
            name=body.name or "",
        )
    else:
        conversation = await service.create_direct(
            creator_id=ctx.user.id,
            participant_user_ids=body.participant_user_ids,
            name=body.name,
        )
    return await _to_response(service, conversation)


@router.get("/conversations", response_model=list[ConversationResponse])
async def list_conversations(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    service: Annotated[ConversationService, Depends(get_conversation_service)],
) -> list[ConversationResponse]:
    conversations = await service.list_for_user(ctx.user.id)
    return [await _to_response(service, c) for c in conversations]


@router.delete("/conversations/{conversation_id}", status_code=204)
async def delete_conversation(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    conversation_id: UUID,
    service: Annotated[ConversationService, Depends(get_conversation_service)],
) -> Response:
    """Leave a conversation the caller is an active participant of (FR-055).

    A per-user soft delete: stamps only the caller's membership `left_at` — the
    conversation, the other participant's membership, and all messages stay
    intact (NO cascade). The conversation disappears from the caller's list and
    reappears (with the peer's new message) when the peer next sends into it.
    Participant authorization is enforced in the service layer (Constitution
    §8). Returns 204 on success; 404 when the conversation does not exist; 403
    when the caller is not an active participant.
    """
    await service.delete_conversation(requester_id=ctx.user.id, conversation_id=conversation_id)
    return Response(status_code=204)


@router.post(
    "/conversations/{conversation_id}/participants",
    response_model=ConversationParticipantResponse,
    status_code=201,
)
async def add_participant(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    conversation_id: UUID,
    body: AddParticipantRequest,
    service: Annotated[ConversationService, Depends(get_conversation_service)],
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
) -> ConversationParticipantResponse:
    """Add a member to a group conversation (FR-024, group_admin only).

    Emits `conversation.participant_added` to every active member (including
    the new one) so their clients know to (re)issue a group-key epoch —
    T068/websocket-events.md.
    """
    participant = await service.add_participant(
        conversation_id=conversation_id, actor_id=ctx.user.id, target_user_id=body.user_id
    )
    event: dict[str, object] = {
        "type": "conversation.participant_added",
        "data": {
            "conversation_id": str(conversation_id),
            "user_id": str(body.user_id),
            "added_by": str(ctx.user.id),
        },
    }
    for p in await service.list_participants(conversation_id):
        await connection_manager.send_to_user(p.user_id, event)
    # Resolve the new member's public name so the 201 response carries a label
    # directly (the WS event itself stays id-only; clients re-fetch the
    # conversation list on membership change, which now includes names).
    added_user = await user_repo.get_by_id(body.user_id)
    return _participant_to_response(
        participant,
        username=added_user.username if added_user else None,
        display_name=added_user.display_name if added_user else None,
    )


@router.delete("/conversations/{conversation_id}/participants/{user_id}", status_code=204)
async def remove_participant(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    conversation_id: UUID,
    user_id: UUID,
    service: Annotated[ConversationService, Depends(get_conversation_service)],
) -> Response:
    """Remove a member from a group conversation, or let a member leave
    themselves (FR-024/FR-028, group_admin-or-self).

    The recipient snapshot is taken *before* removal so the removed member is
    also notified (their client needs the event even though they're no longer
    in the post-removal active list) — websocket-events.md's
    `conversation.participant_removed` contract.
    """
    recipients = [p.user_id for p in await service.list_participants(conversation_id)]
    await service.remove_participant(
        conversation_id=conversation_id, actor_id=ctx.user.id, target_user_id=user_id
    )
    event: dict[str, object] = {
        "type": "conversation.participant_removed",
        "data": {
            "conversation_id": str(conversation_id),
            "user_id": str(user_id),
            "removed_by": str(ctx.user.id),
        },
    }
    for uid in recipients:
        await connection_manager.send_to_user(uid, event)
    return Response(status_code=204)
