/**
 * Messaging DTOs (US2 / Phase 5) — mirror `backend/src/schemas/messaging.py`.
 *
 * Field names are snake_case to match the backend's Pydantic serialization. The
 * `ciphertext` and `envelope` fields are **opaque** transport blobs: the backend
 * stores/relays them without parsing (FR-051/SC-002). Plaintext only ever exists
 * behind `src/crypto/` in the browser.
 */

export interface MessageEnvelope {
  alg: string;
  nonce: string; // base64
  version: number;
  /**
   * Opaque, algorithm-specific crypto material the backend never inspects. For
   * Grade A this carries the ML-KEM-768 ciphertext (on the first/keying message)
   * and the ML-DSA-65 message signature.
   */
  [extra: string]: unknown;
}

export interface PublishIdentityKeyRequest {
  device_label: string;
  public_signing_key: string; // base64
  public_kem_key: string; // base64
  /**
   * FR-054: optional password-wrapped private keypair (opaque to the backend).
   * When provided as a complete set, the wrapped blobs + wrap parameters are
   * stored verbatim so the same identity can be recovered on another device
   * via the password. All-or-none — a partial set is rejected by the server.
   */
  wrapped_signing_private_key?: string | null; // base64
  wrapped_kem_private_key?: string | null; // base64
  wrap_nonce?: string | null; // base64
  wrap_kdf_salt?: string | null; // base64
  wrap_kdf_params?: string | null; // e.g. "argon2id:t=3:m=65536:p=4"
  wrap_alg?: string | null; // e.g. "aes-256-gcm"
}

export interface RotateIdentityKeyRequest {
  new_public_signing_key: string; // base64
  new_public_kem_key: string; // base64
  rotation_attestation: string; // base64
  // FR-054: re-wrapped private keypair under the (unchanged) password key.
  wrapped_signing_private_key?: string | null; // base64
  wrapped_kem_private_key?: string | null; // base64
  wrap_nonce?: string | null; // base64
  wrap_kdf_salt?: string | null; // base64
  wrap_kdf_params?: string | null;
  wrap_alg?: string | null;
}

export interface IdentityKeyResponse {
  id: string;
  user_id: string;
  device_label: string;
  public_signing_key: string; // base64
  public_kem_key: string; // base64
  key_version: number;
  created_at: string;
  superseded_at: string | null;
  /**
   * FR-054: wrapped private material. Present only on auth-scoped responses
   * (`GET /users/me/identity-key`, publish, rotate); the public directory
   * `GET /users/{user_id}/identity-keys` never includes these fields. Null
   * for legacy / non-recovering publishes.
   */
  wrapped_signing_private_key?: string | null; // base64
  wrapped_kem_private_key?: string | null; // base64
  wrap_nonce?: string | null; // base64
  wrap_kdf_salt?: string | null; // base64
  wrap_kdf_params?: string | null;
  wrap_alg?: string | null;
}

/**
 * Directory view of an identity key — public material only (FR-054 boundary).
 * Returned by `GET /users/{user_id}/identity-keys`; never carries wrapped
 * private keys. Structurally a subset of `IdentityKeyResponse`.
 */
export interface PublicIdentityKeyResponse {
  id: string;
  user_id: string;
  device_label: string;
  public_signing_key: string; // base64
  public_kem_key: string; // base64
  key_version: number;
  created_at: string;
  superseded_at: string | null;
}

/**
 * Password-recoverable backup of a conversation's message key (extends FR-054's
 * identity-key recovery to the 1:1 conversation symmetric key). Opaque to the
 * server — it stores and relays the wrapped blob but never decrypts it.
 */
export interface PutConversationKeyBackupRequest {
  wrapped_key: string; // base64
  wrap_nonce: string; // base64
  wrap_kdf_salt: string; // base64
  wrap_kdf_params: string;
  wrap_alg: string;
}

export interface ConversationKeyBackupResponse {
  conversation_id: string;
  wrapped_key: string; // base64
  wrap_nonce: string; // base64
  wrap_kdf_salt: string; // base64
  wrap_kdf_params: string;
  wrap_alg: string;
  created_at: string;
  updated_at: string;
}

export interface CreateConversationRequest {
  /** "direct" (US2) requires exactly one other participant and no name;
   * "group" (US3, FR-024) requires a name and at least one other participant
   * besides the creator. */
  type: "direct" | "group";
  participant_user_ids: string[];
  name: string | null;
}

/** FR-024: add a member to a group conversation (group_admin only). */
export interface AddParticipantRequest {
  user_id: string;
}

export interface ConversationParticipantResponse {
  user_id: string;
  role: string | null;
  joined_at: string;
  /**
   * Public handle + friendly name, joined server-side from the users table so
   * the UI can render participant labels immediately without a per-peer
   * `GET /users/{id}` round-trip (which flashed a truncated-id while the
   * in-memory name map was empty on refresh). Optional: older responses without
   * them stay valid; the store falls back to per-peer resolution then.
   */
  username?: string | null;
  display_name?: string | null;
}

export interface ConversationResponse {
  id: string;
  type: string;
  name: string | null;
  created_by: string;
  created_at: string;
  /**
   * FR-058: timestamp of the most recent message, used to order the conversation
   * list newest-first and to display last-activity time. The server provides
   * ONLY this timestamp — the latest-message *preview* is decrypted client-side
   * (FR-051); the server stores only ciphertext and cannot produce a readable
   * preview. Null for conversations with no messages yet. Optional on the client
   * so legacy literals (and older server responses) stay valid.
   */
  last_message_at?: string | null;
  participants: ConversationParticipantResponse[];
}

export interface SendMessageRequest {
  ciphertext: string; // base64
  envelope: MessageEnvelope;
  sender_identity_key_id: string;
}

export interface MessageResponse {
  id: string;
  conversation_id: string;
  sender_id: string;
  sender_identity_key_id: string;
  ciphertext: string; // base64
  envelope: MessageEnvelope;
  sent_at: string;
}

export interface MessageListResponse {
  messages: MessageResponse[];
  next_cursor: string | null;
}

/**
 * US4 file/image sharing. A share creates a companion `Message` row (envelope
 * `kind: "file"` + `file_attachment_id`) so it sorts into the normal timeline
 * and WS fan-out — the response below is what `POST
 * /conversations/{id}/files` returns for the upload itself.
 */
export interface FileUploadResponse {
  file_attachment_id: string;
  message_id: string;
  content_type: string;
  size_bytes: number;
  upload_status: "pending" | "complete" | "failed";
  sent_at: string;
}

// ---- WebSocket event contract (contracts/websocket-events.md) -------------

export interface WsEvent<T extends string = string, D = Record<string, unknown>> {
  type: T;
  data: D;
}

export interface MessageNewData {
  conversation_id: string;
  message_id: string;
  sender_id: string;
  sender_identity_key_id: string;
  ciphertext: string; // base64
  envelope: MessageEnvelope;
  sent_at: string;
}

export interface WsErrorData {
  error_code: string;
  message: string;
}

/** US3 (T068): group-membership change events — clients treat these as a
 * group-key-epoch rotation trigger (websocket-events.md). */
export interface ParticipantAddedData {
  conversation_id: string;
  user_id: string;
  added_by: string;
}

export interface ParticipantRemovedData {
  conversation_id: string;
  user_id: string;
  removed_by: string;
}