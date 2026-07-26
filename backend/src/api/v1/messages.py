"""Message endpoints — send + list ciphertext messages (US2).

`ciphertext` and `envelope` are opaque to the backend (FR-051/SC-002): they are
transported as base64 / JSON and stored verbatim, never parsed for content.
Pagination is cursor-based on `(sent_at, id)` via the `before` query param
(FR-034). Authorization (participant-only) is enforced in MessagingService.
"""

import base64
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.ws.connection_manager import connection_manager
from src.core.dependencies import (
    AuthContext,
    get_conversation_key_backup_service,
    get_current_session,
    get_messaging_service,
)
from src.models.conversation_key_backup import ConversationKeyBackup
from src.schemas.messaging import (
    ConversationKeyBackupResponse,
    MessageListResponse,
    MessageResponse,
    PutConversationKeyBackupRequest,
    SendMessageRequest,
)
from src.services.conversation_key_backup_service import ConversationKeyBackupService
from src.services.messaging_service import (
    MessagingService,
    message_to_response,
    message_to_ws_event,
)

router = APIRouter()


def _to_key_backup_response(record: ConversationKeyBackup) -> ConversationKeyBackupResponse:
    return ConversationKeyBackupResponse(
        conversation_id=record.conversation_id,
        wrapped_key=base64.b64encode(record.wrapped_key).decode("ascii"),
        wrap_nonce=base64.b64encode(record.wrap_nonce).decode("ascii"),
        wrap_kdf_salt=base64.b64encode(record.wrap_kdf_salt).decode("ascii"),
        wrap_kdf_params=record.wrap_kdf_params,
        wrap_alg=record.wrap_alg,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=MessageResponse,
    status_code=201,
)
async def send_message(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    conversation_id: UUID,
    body: SendMessageRequest,
    service: Annotated[MessagingService, Depends(get_messaging_service)],
) -> MessageResponse:
    # Envelope is validated as a MessageEnvelope by Pydantic at the request
    # boundary; persist its raw dict so the opaque crypto material round-trips.
    message, recipients = await service.send(
        sender_id=ctx.user.id,
        conversation_id=conversation_id,
        ciphertext_b64=body.ciphertext,
        envelope=body.envelope.model_dump(),
        sender_identity_key_id=body.sender_identity_key_id,
    )

    # Fan out `message.new` over the websocket the same way the WS-native send
    # path does (src.api.ws.realtime._handle_message_send) — otherwise a
    # message sent through this REST endpoint never reaches a recipient's
    # already-open socket, and only shows up on their next manual refetch.
    event = message_to_ws_event(message)
    for recipient_id in recipients:
        if recipient_id == ctx.user.id:
            continue
        await connection_manager.send_to_user(recipient_id, event)

    return message_to_response(message)


@router.get(
    "/conversations/{conversation_id}/messages",
    response_model=MessageListResponse,
)
async def list_messages(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    conversation_id: UUID,
    service: Annotated[MessagingService, Depends(get_messaging_service)],
    before: Annotated[str | None, Query(description="Cursor for the next older page")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> MessageListResponse:
    return await service.list_messages(
        requester_id=ctx.user.id,
        conversation_id=conversation_id,
        before_cursor=before,
        limit=limit,
    )


@router.put(
    "/conversations/{conversation_id}/key-backup",
    response_model=ConversationKeyBackupResponse,
)
async def put_conversation_key_backup(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    conversation_id: UUID,
    body: PutConversationKeyBackupRequest,
    service: Annotated[ConversationKeyBackupService, Depends(get_conversation_key_backup_service)],
) -> ConversationKeyBackupResponse:
    # Opaque to the server (FR-051/SC-002 extended, mirrors FR-054): the wrapped
    # message key is stored and relayed verbatim, never decrypted here.
    record = await service.put(
        conversation_id=conversation_id,
        user_id=ctx.user.id,
        wrapped_key=base64.b64decode(body.wrapped_key, validate=True),
        wrap_nonce=base64.b64decode(body.wrap_nonce, validate=True),
        wrap_kdf_salt=base64.b64decode(body.wrap_kdf_salt, validate=True),
        wrap_kdf_params=body.wrap_kdf_params,
        wrap_alg=body.wrap_alg,
    )
    return _to_key_backup_response(record)


@router.get(
    "/conversations/{conversation_id}/key-backup",
    response_model=ConversationKeyBackupResponse,
)
async def get_conversation_key_backup(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    conversation_id: UUID,
    service: Annotated[ConversationKeyBackupService, Depends(get_conversation_key_backup_service)],
) -> ConversationKeyBackupResponse:
    record = await service.get(conversation_id=conversation_id, user_id=ctx.user.id)
    if record is None:
        raise HTTPException(status_code=404, detail="no key backup for this conversation")
    return _to_key_backup_response(record)
