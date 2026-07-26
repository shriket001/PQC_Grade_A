"""WebSocket realtime endpoint — `/api/v1/ws` (US2, T060).

Connection is authenticated at upgrade time with the access token (query param
`access_token`), and the referenced session is confirmed active in the DB — so
a revoked session is rejected even before its short access TTL elapses (defense
in depth, Constitution §8). Every inbound event is still authorized server-side
(Zero Trust): `message.send` is persisted through MessagingService, which
re-checks participant membership before storing.

Content-bearing events carry the same opaque `ciphertext` + `envelope` shape as
the REST contract; the server relays them without inspection (research.md #1,
websocket-events.md). Fan-out across instances uses the ConnectionManager's
Redis Pub/Sub channels (research.md #2).
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from src.api.ws.connection_manager import connection_manager
from src.core.database import session_scope
from src.crypto.factory import get_token_signer
from src.repositories.conversation_repository import ConversationRepository
from src.repositories.identity_key_repository import IdentityKeyRepository
from src.repositories.message_repository import MessageRepository
from src.repositories.session_repository import SessionRepository
from src.repositories.user_repository import UserRepository
from src.schemas.messaging import MessageEnvelope
from src.services import access_tokens
from src.services.access_tokens import InvalidAccessTokenError
from src.services.messaging_errors import MessagingError
from src.services.messaging_service import MessagingService, message_to_ws_event

router = APIRouter()

_CLOSE_POLICY_VIOLATION = 1008


async def _authenticate(websocket: WebSocket) -> UUID | None:
    """Resolve the access token to an active user id, or None on failure.

    Done before `accept()` so a bad token never opens a connection.
    """
    token = websocket.query_params.get("access_token")
    if not token:
        return None
    try:
        claims = access_tokens.decode(get_token_signer(), token)
    except InvalidAccessTokenError:
        return None
    async with session_scope() as session:
        session_repo = SessionRepository(session)
        user_repo = UserRepository(session)
        sess = await session_repo.get_by_id(claims.session_id)
        if sess is None or not sess.is_active:
            return None
        user = await user_repo.get_by_id(claims.user_id)
        if user is None:
            return None
        return user.id


def _error_event(error_code: str, message: str) -> dict[str, Any]:
    return {"type": "error", "data": {"error_code": error_code, "message": message}}


async def _handle_message_send(websocket: WebSocket, sender_id: UUID, data: dict[str, Any]) -> None:
    # Required opaque fields (FR-051): the server relays these without inspecting
    # content; only the structural envelope is validated.
    try:
        conversation_id = UUID(str(data["conversation_id"]))
        ciphertext_b64 = str(data["ciphertext"])
        sender_identity_key_id = UUID(str(data["sender_identity_key_id"]))
        envelope = MessageEnvelope.model_validate(data["envelope"])
    except (KeyError, ValueError, ValidationError):
        await websocket.send_json(_error_event("invalid_envelope", "malformed message.send"))
        return

    async with session_scope() as session:
        service = MessagingService(
            message_repo=MessageRepository(session),
            conversation_repo=ConversationRepository(session),
            identity_key_repo=IdentityKeyRepository(session),
        )
        try:
            message, recipient_ids = await service.send(
                sender_id=sender_id,
                conversation_id=conversation_id,
                ciphertext_b64=ciphertext_b64,
                envelope=envelope.model_dump(),
                sender_identity_key_id=sender_identity_key_id,
            )
        except MessagingError as err:
            await websocket.send_json(_error_event(err.error_code, err.message))
            return

    # Fan out `message.new` to every other active participant; the sender's own
    # client already holds the plaintext it just encrypted.
    event = message_to_ws_event(message)
    for recipient_id in recipient_ids:
        if recipient_id == sender_id:
            continue
        await connection_manager.send_to_user(recipient_id, event)


@router.websocket("/api/v1/ws")
async def realtime(websocket: WebSocket) -> None:
    user_id = await _authenticate(websocket)
    if user_id is None:
        # Reject the upgrade before accepting — no connection is opened.
        await websocket.close(code=_CLOSE_POLICY_VIOLATION)
        return

    await connection_manager.connect(user_id, websocket)
    try:
        while True:
            try:
                raw = await websocket.receive_json()
            except WebSocketDisconnect:
                break
            if not isinstance(raw, dict):
                continue
            event_type = raw.get("type")
            raw_data = raw.get("data")
            data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
            if event_type == "message.send":
                await _handle_message_send(websocket, user_id, data)
            # typing.start/stop, message.read, presence.heartbeat land with the
            # later realtime stories (US2 ships message.send/message.new only).
            elif event_type is not None:
                await websocket.send_json(
                    _error_event("unknown_event", f"unsupported event: {event_type}")
                )
    except WebSocketDisconnect:
        pass
    finally:
        await connection_manager.disconnect(user_id, websocket)
