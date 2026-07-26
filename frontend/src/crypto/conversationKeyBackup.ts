/**
 * Conversation-key backup — extends FR-054's password-recoverable identity to
 * the 1:1 conversation symmetric key (see `backend/src/models/conversation_key_backup.py`
 * for the server-side rationale).
 *
 * The recipient side of a 1:1 conversation can always re-derive its message key
 * later by decapsulating the KEM ciphertext embedded in the conversation's
 * first message — their KEM private key is itself recoverable via the
 * password-wrapped identity. The INITIATOR side cannot: their copy of the
 * derived key is a one-time local secret with no ciphertext to redo
 * decapsulation against. Wrapping that key under the same password-derived
 * `wrapKey` as the identity (see `identityWrap.ts`) and pushing the opaque
 * blob to the server closes that gap — any browser that knows the password
 * can recover it, exactly like the identity itself.
 */

import { aes256GcmMessageCipher } from "@/crypto/providers/ciphers";
import { base64ToBytes, bytesToBase64 } from "@/crypto/bytes";
import type { ConversationKeyBackupResponse, PutConversationKeyBackupRequest } from "@/types/messaging";

/** Wrap a conversation's message key under `wrapKey`, AAD-bound to the
 * conversation id (substitution resistance — a backup blob from one
 * conversation can't be replayed as another's). */
export async function wrapConversationKey(
  wrapKey: Uint8Array,
  wrapKdfSalt: Uint8Array,
  wrapKdfParams: string,
  messageKey: Uint8Array,
  conversationId: string,
): Promise<PutConversationKeyBackupRequest> {
  const aad = new TextEncoder().encode(conversationId);
  const { ciphertext, nonce } = await aes256GcmMessageCipher.encrypt(
    wrapKey,
    messageKey,
    aad,
  );
  return {
    wrapped_key: bytesToBase64(ciphertext),
    wrap_nonce: bytesToBase64(nonce),
    wrap_kdf_salt: bytesToBase64(wrapKdfSalt),
    wrap_kdf_params: wrapKdfParams,
    wrap_alg: "aes-256-gcm",
  };
}

/** Unwrap a conversation's message key backup fetched from the server. Throws
 * if `wrapKey` is wrong or the backup was written for a different conversation
 * id (AAD mismatch fails the Poly1305 tag). */
export async function unwrapConversationKey(
  wrapKey: Uint8Array,
  backup: ConversationKeyBackupResponse,
  conversationId: string,
): Promise<Uint8Array> {
  const aad = new TextEncoder().encode(conversationId);
  return aes256GcmMessageCipher.decrypt(
    wrapKey,
    { ciphertext: base64ToBytes(backup.wrapped_key), nonce: base64ToBytes(backup.wrap_nonce) },
    aad,
  );
}
