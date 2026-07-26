"""File-sharing endpoints — encrypted upload/download (US4).

`file_envelope`/the uploaded ciphertext are opaque to the backend
(FR-051/SC-002): they are stored/relayed verbatim, never parsed for content.
Authorization (participant-only) is enforced in `FileService`.
"""

import json
from io import BytesIO
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.responses import StreamingResponse

from src.api.ws.connection_manager import connection_manager
from src.core.dependencies import AuthContext, get_current_session, get_file_service
from src.schemas.messaging import FileUploadResponse
from src.services.file_errors import FileError
from src.services.file_service import FileService
from src.services.messaging_service import message_to_ws_event

router = APIRouter()


@router.post(
    "/conversations/{conversation_id}/files",
    response_model=FileUploadResponse,
    status_code=201,
)
async def upload_file(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    conversation_id: UUID,
    service: Annotated[FileService, Depends(get_file_service)],
    sender_identity_key_id: Annotated[UUID, Form()],
    file_envelope: Annotated[str, Form()],
    content_type: Annotated[str, Form()],
    size_bytes: Annotated[int, Form()],
    file_ciphertext: Annotated[UploadFile, File()],
) -> FileUploadResponse:
    try:
        envelope_dict = json.loads(file_envelope)
    except json.JSONDecodeError as err:
        raise FileError("file_envelope must be valid JSON") from err

    message, attachment, recipients = await service.upload(
        conversation_id=conversation_id,
        sender_id=ctx.user.id,
        sender_identity_key_id=sender_identity_key_id,
        file_envelope=envelope_dict,
        content_type=content_type,
        declared_size_bytes=size_bytes,
        fileobj=file_ciphertext.file,
    )

    # Fan out `message.new` the same way MessagingService.send does, so the
    # file/image bubble appears live for recipients with an open socket.
    event = message_to_ws_event(message)
    for recipient_id in recipients:
        if recipient_id == ctx.user.id:
            continue
        await connection_manager.send_to_user(recipient_id, event)

    return FileUploadResponse(
        file_attachment_id=attachment.id,
        message_id=message.id,
        content_type=attachment.content_type,
        size_bytes=attachment.size_bytes,
        upload_status=attachment.upload_status.value,
        sent_at=message.sent_at,
    )


@router.get("/conversations/{conversation_id}/files/{file_id}")
async def download_file(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    conversation_id: UUID,
    file_id: UUID,
    service: Annotated[FileService, Depends(get_file_service)],
) -> StreamingResponse:
    attachment, data = await service.download(
        conversation_id=conversation_id, file_id=file_id, user_id=ctx.user.id
    )
    return StreamingResponse(
        BytesIO(data),
        media_type="application/octet-stream",
        headers={
            "X-File-Envelope": json.dumps(attachment.envelope),
            "X-File-Content-Type": attachment.content_type,
            "X-File-Size-Bytes": str(attachment.size_bytes),
        },
    )
