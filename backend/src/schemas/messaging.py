"""Messaging DTOs (US2 / Phase 5).

The `ciphertext` and `envelope` fields are **opaque** to the backend: they are
transported as base64 / JSON and stored verbatim, never parsed for content
(FR-051 / SC-002). `MessageEnvelope` is the one typed model that touches the
envelope — it validates only the structural fields (`alg`, `nonce`, `version`)
the backend needs to record ingest integrity; everything else passes through
with `extra="allow"` so the algorithm-specific crypto material stays opaque to
the server (Constitution Principle VII — no bare dict, but no content peeking).
"""

from datetime import datetime
from uuid import UUID

from pydantic import Field, model_validator

from src.schemas.base import BaseSchema


class MessageEnvelope(BaseSchema):
    """Algorithm-agnostic envelope. The backend validates only the structural
    fields below; any additional crypto material (KEM ciphertext, key IDs, …)
    is carried through opaquely and never inspected (FR-051)."""

    model_config = {**BaseSchema.model_config, "extra": "allow"}

    alg: str = Field(min_length=1, max_length=64)
    nonce: str = Field(min_length=1, max_length=256)  # base64
    version: int = Field(ge=1, le=100)


class PublishIdentityKeyRequest(BaseSchema):
    device_label: str = Field(min_length=1, max_length=100)
    public_signing_key: str = Field(min_length=1, max_length=8192)  # base64
    public_kem_key: str = Field(min_length=1, max_length=8192)  # base64
    # FR-054: optional password-wrapped private keypair (opaque to the server).
    # When provided, the wrapped blobs + wrap parameters are stored verbatim so
    # the same identity can be recovered on another device via the password.
    wrapped_signing_private_key: str | None = Field(default=None, max_length=32768)  # base64
    wrapped_kem_private_key: str | None = Field(default=None, max_length=32768)  # base64
    wrap_nonce: str | None = Field(default=None, max_length=256)  # base64
    wrap_kdf_salt: str | None = Field(default=None, max_length=256)  # base64
    wrap_kdf_params: str | None = Field(default=None, max_length=64)
    wrap_alg: str | None = Field(default=None, max_length=32)


class RotateIdentityKeyRequest(BaseSchema):
    new_public_signing_key: str = Field(min_length=1, max_length=8192)  # base64
    new_public_kem_key: str = Field(min_length=1, max_length=8192)  # base64
    # Signature by the outgoing ML-DSA-65 private key over the concatenation
    # of the two new public keys (FR-049). Verified server-side with the
    # outgoing *public* signing key — the backend never holds a private key.
    rotation_attestation: str = Field(min_length=1, max_length=8192)  # base64
    # FR-054: re-wrapped private keypair under the (unchanged) password key.
    wrapped_signing_private_key: str | None = Field(default=None, max_length=32768)  # base64
    wrapped_kem_private_key: str | None = Field(default=None, max_length=32768)  # base64
    wrap_nonce: str | None = Field(default=None, max_length=256)  # base64
    wrap_kdf_salt: str | None = Field(default=None, max_length=256)  # base64
    wrap_kdf_params: str | None = Field(default=None, max_length=64)
    wrap_alg: str | None = Field(default=None, max_length=32)


class PublicIdentityKeyResponse(BaseSchema):
    """Directory view of an identity key — public material only.

    Returned by the public `GET /users/{user_id}/identity-keys` endpoint. It
    MUST NOT carry wrapped private keys (FR-054 security boundary): wrapped
    material is only ever returned by the auth-scoped `/users/me/identity-key`
    and publish/rotate responses.
    """

    id: UUID
    user_id: UUID
    device_label: str
    public_signing_key: str  # base64
    public_kem_key: str  # base64
    key_version: int
    created_at: datetime
    superseded_at: datetime | None = None


class IdentityKeyResponse(PublicIdentityKeyResponse):
    """Auth-scoped view — adds the optional wrapped private-key material (FR-054).

    Only ever returned to the authenticated owner (`/users/me/identity-key`,
    publish, rotate); never exposed via the public directory.
    """

    wrapped_signing_private_key: str | None = None  # base64
    wrapped_kem_private_key: str | None = None  # base64
    wrap_nonce: str | None = None  # base64
    wrap_kdf_salt: str | None = None  # base64
    wrap_kdf_params: str | None = None
    wrap_alg: str | None = None


class PutConversationKeyBackupRequest(BaseSchema):
    """Push the caller's wrapped per-conversation message key (extends FR-054's
    identity-key recovery to the 1:1 conversation symmetric key — see
    `ConversationKeyBackup`). All fields are opaque to the server and required:
    there is no meaningful "half-backed-up" state for a single key blob."""

    wrapped_key: str = Field(min_length=1, max_length=4096)  # base64
    wrap_nonce: str = Field(min_length=1, max_length=256)  # base64
    wrap_kdf_salt: str = Field(min_length=1, max_length=256)  # base64
    wrap_kdf_params: str = Field(min_length=1, max_length=64)
    wrap_alg: str = Field(min_length=1, max_length=32)


class ConversationKeyBackupResponse(BaseSchema):
    conversation_id: UUID
    wrapped_key: str  # base64
    wrap_nonce: str  # base64
    wrap_kdf_salt: str  # base64
    wrap_kdf_params: str
    wrap_alg: str
    created_at: datetime
    updated_at: datetime


class CreateConversationRequest(BaseSchema):
    """ "direct" (US2) requires exactly one other participant and no name;
    "group" (US3, FR-024) requires a name and at least one other participant
    besides the creator. The 64-participant cap is a reasonable operational
    limit (spec Assumptions), not a product-scope decision."""

    type: str = Field(pattern="^(direct|group)$")
    participant_user_ids: list[UUID] = Field(min_length=1, max_length=64)
    name: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _validate_shape(self) -> "CreateConversationRequest":
        if self.type == "direct":
            if len(self.participant_user_ids) != 1:
                raise ValueError("a direct conversation requires exactly one other participant")
            if self.name is not None:
                raise ValueError("a direct conversation may not have a name")
        elif not self.name or not self.name.strip():
            raise ValueError("a group conversation requires a name")
        return self


class AddParticipantRequest(BaseSchema):
    """FR-024: add a member to a group conversation (group_admin only)."""

    user_id: UUID


class ConversationParticipantResponse(BaseSchema):
    user_id: UUID
    role: str | None
    joined_at: datetime
    # Public handle + friendly name, joined from the `users` table so the
    # client can render participant labels immediately without a per-peer
    # `GET /users/{id}` round-trip (which left a truncated-id flash on
    # refresh while the in-memory name map was empty). Optional + nullable:
    # usernames are already public (`GET /users/{id}`, `/users/search`), and
    # older callers/responses that don't carry them stay valid.
    username: str | None = None
    display_name: str | None = None


class ConversationResponse(BaseSchema):
    id: UUID
    type: str
    name: str | None
    created_by: UUID
    created_at: datetime
    # FR-058: timestamp of the most recent message, for list ordering (newest
    # first) + displayed time. The server provides ONLY this timestamp — the
    # latest-message preview is decrypted client-side (FR-051). Null for
    # conversations with no messages yet.
    last_message_at: datetime | None = None
    participants: list[ConversationParticipantResponse]


class SendMessageRequest(BaseSchema):
    ciphertext: str = Field(min_length=1, max_length=1024 * 1024)  # base64
    envelope: MessageEnvelope
    sender_identity_key_id: UUID


class MessageResponse(BaseSchema):
    id: UUID
    conversation_id: UUID
    sender_id: UUID
    sender_identity_key_id: UUID
    ciphertext: str  # base64
    envelope: MessageEnvelope
    sent_at: datetime


class MessageListResponse(BaseSchema):
    messages: list[MessageResponse]
    next_cursor: str | None = None


class FileUploadResponse(BaseSchema):
    """Response to `POST /conversations/{id}/files` (US4). The companion
    message (`message_id`) is what recipients see in the normal message
    timeline/WS fan-out; `file_attachment_id` is what `GET
    /conversations/{id}/files/{file_id}` expects."""

    file_attachment_id: UUID
    message_id: UUID
    content_type: str
    size_bytes: int
    upload_status: str
    sent_at: datetime
