/**
 * Conversation crypto — the E2EE heart of US2 (T051, T061a).
 *
 * Per conversation, a 32-byte AES-256-GCM message key is derived once from
 * an ML-KEM-768 shared secret and reused for the life of the (1:1 MVP)
 * conversation. A full Double Ratchet (per-message key advances + post-compromise
 * security) is a documented MVP deferral — the key-establishment + AEAD here is
 * the spec-required baseline.
 *
 * Key establishment (1:1, initiator-driven):
 *   - Initiator: encapsulate(peer KEM pub) → (kemCiphertext, sharedSecret).
 *     The kemCiphertext rides in the *first* message's envelope so the peer can
 *     decapsulate; subsequent messages omit it.
 *   - Recipient: decapsulate(kemCiphertext, my KEM priv) → sharedSecret.
 *   - Both: messageKey = HKDF-SHA3-256(sharedSecret, info="vayunx/grade-a/message/v1", 32).
 *
 * Per message:
 *   - AEAD: AES-256-GCM(key=messageKey, nonce=random12, aad = `${convId}|${senderKeyId}`).
 *   - Authorship: ML-DSA-65 signature over concat(ciphertext, nonce, aad), carried
 *     in `envelope.sig`; the recipient verifies it with the sender's signing
 *     public key (FR-027: authenticity is a client-side concern).
 *
 * All private key material stays behind this boundary (FR-051/SC-002).
 */

import { aes256GcmMessageCipher } from "@/crypto/providers/ciphers";
import { hkdfSha3256KeyDerivationFunction } from "@/crypto/providers/kdf";
import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { mlKem768KeyExchangeProvider } from "@/crypto/providers/keyExchangeProvider";
import { base64ToBytes, bytesToBase64, concatBytes } from "@/crypto/bytes";
import type { LocalIdentity } from "@/crypto/vault";
import type { MessageEnvelope, MessageResponse } from "@/types/messaging";

const ALG = "aes-256-gcm";
const VERSION = 1;
const HKDF_INFO = new TextEncoder().encode("vayunx/grade-a/message/v1");
const KEY_LENGTH = 32;
const CONV_KEY_PREFIX = "vayunx.convkey.";

export interface PeerPublicKeys {
  signingPublicKey: Uint8Array;
  kemPublicKey: Uint8Array;
}

export interface ConversationKeyMaterial {
  messageKey: Uint8Array;
  peerSigningPublicKey: Uint8Array;
}

async function deriveMessageKey(sharedSecret: Uint8Array): Promise<Uint8Array> {
  return hkdfSha3256KeyDerivationFunction.derive(sharedSecret, HKDF_INFO, KEY_LENGTH);
}

/** Initiator side: encapsulate against the peer's KEM public key. */
export async function establishOutbound(
  peerKemPublicKey: Uint8Array,
): Promise<{ messageKey: Uint8Array; kemCiphertext: Uint8Array }> {
  const { ciphertext, sharedSecret } = await mlKem768KeyExchangeProvider.encapsulate(
    peerKemPublicKey,
  );
  const messageKey = await deriveMessageKey(sharedSecret);
  return { messageKey, kemCiphertext: ciphertext };
}

/** Recipient side: decapsulate the KEM ciphertext from the first message. */
export async function establishInbound(
  kemCiphertext: Uint8Array,
  myKemPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  const sharedSecret = await mlKem768KeyExchangeProvider.decapsulate(
    myKemPrivateKey,
    kemCiphertext,
  );
  return deriveMessageKey(sharedSecret);
}

function associatedData(conversationId: string, senderKeyId: string): Uint8Array {
  return new TextEncoder().encode(`${conversationId}|${senderKeyId}`);
}

export interface SealedMessage {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  signature: Uint8Array;
}

/** Encrypt + sign one message under an established conversation key. */
export async function sealMessage(
  messageKey: Uint8Array,
  plaintext: Uint8Array,
  signingPrivateKey: Uint8Array,
  conversationId: string,
  senderKeyId: string,
): Promise<SealedMessage> {
  const aad = associatedData(conversationId, senderKeyId);
  const { ciphertext, nonce } = await aes256GcmMessageCipher.encrypt(
    messageKey,
    plaintext,
    aad,
  );
  const signature = await mlDsa65IdentityKeyProvider.sign(
    signingPrivateKey,
    concatBytes(ciphertext, nonce, aad),
  );
  return { ciphertext, nonce, signature };
}

/** Verify authorship + decrypt one message under an established conversation key.
 *
 * Returns the plaintext, or throws `MessageAuthenticityError` if the signature
 * does not verify against the sender's public signing key (FR-027).
 */
export async function openMessage(
  messageKey: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  signature: Uint8Array,
  senderSigningPublicKey: Uint8Array,
  conversationId: string,
  senderKeyId: string,
): Promise<Uint8Array> {
  const aad = associatedData(conversationId, senderKeyId);
  const valid = await mlDsa65IdentityKeyProvider.verify(
    senderSigningPublicKey,
    concatBytes(ciphertext, nonce, aad),
    signature,
  );
  if (!valid) {
    throw new MessageAuthenticityError("signature did not verify");
  }
  return aes256GcmMessageCipher.decrypt(messageKey, { ciphertext, nonce }, aad);
}

export class MessageAuthenticityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MessageAuthenticityError";
  }
}

// ---- Envelope build / parse -----------------------------------------------

export interface PreparedOutgoing {
  ciphertextB64: string;
  envelope: MessageEnvelope;
  /** True when this is the keying (first) message that carries the KEM ciphertext. */
  keying: boolean;
}

/**
 * Prepare an outgoing message for a conversation. If no key is established yet
 * (the local user is initiating), encapsulate against the peer's KEM public key
 * and include the KEM ciphertext in the envelope. Otherwise reuse the stored key.
 */
export async function prepareOutgoing(
  conversationId: string,
  peer: PeerPublicKeys | null,
  plaintext: Uint8Array,
  identity: LocalIdentity,
  existingKey: ConversationKeyMaterial | null,
): Promise<{ prepared: PreparedOutgoing; key: ConversationKeyMaterial }> {
  let key: ConversationKeyMaterial;
  let kemCiphertext: Uint8Array | null = null;
  if (existingKey) {
    key = existingKey;
  } else {
    if (!peer) {
      throw new Error("peer public keys required to initiate a conversation");
    }
    const { messageKey, kemCiphertext: kc } = await establishOutbound(peer.kemPublicKey);
    key = { messageKey, peerSigningPublicKey: peer.signingPublicKey };
    kemCiphertext = kc;
  }
  const sealed = await sealMessage(
    key.messageKey,
    plaintext,
    identity.signingPrivateKey,
    conversationId,
    identity.keyId,
  );
  const envelope: MessageEnvelope = {
    alg: ALG,
    nonce: bytesToBase64(sealed.nonce),
    version: VERSION,
    sig: bytesToBase64(sealed.signature),
  };
  if (kemCiphertext) {
    envelope.kem = bytesToBase64(kemCiphertext);
  }
  return {
    prepared: {
      ciphertextB64: bytesToBase64(sealed.ciphertext),
      envelope,
      keying: kemCiphertext !== null,
    },
    key,
  };
}

/**
 * Receive + decrypt an incoming message, establishing the conversation key from
 * the KEM ciphertext on the first (keying) message. Verifies the sender's
 * signature before returning plaintext (FR-027). `fetchSenderSigningKey`
 * resolves a `(senderUserId, senderIdentityKeyId)` pair to the EXACT public
 * signing key that signed this message — not a cached or highest-version key —
 * so a peer rotating/re-keying their identity (e.g. signing in on a new device)
 * does not break verification of messages signed by an earlier key version.
 */
export async function openIncoming(
  message: MessageResponse,
  identity: LocalIdentity,
  existingKey: ConversationKeyMaterial | null,
  fetchSenderSigningKey: (userId: string, keyId: string) => Promise<Uint8Array>,
): Promise<{ plaintext: Uint8Array; key: ConversationKeyMaterial }> {
  const envelope = message.envelope;
  const ciphertext = base64ToBytes(message.ciphertext);
  const nonce = base64ToBytes(String(envelope.nonce));

  // Always resolve the verification key by the message's specific key id — a
  // cached/highest-version key would fail verification once the sender has more
  // than one published key version (key rotation / new device).
  const senderSigningPublicKey = await fetchSenderSigningKey(
    message.sender_id,
    message.sender_identity_key_id,
  );

  let key = existingKey;
  const kemB64 = envelope.kem;
  if (typeof kemB64 === "string") {
    // The envelope carries a KEM ciphertext: treat it as authoritative, even if
    // we already have a cached key for this conversation. This makes the
    // protocol self-healing when a peer legitimately re-initiates a new key
    // (e.g. after a real device reset) instead of silently producing decrypt
    // failures by reusing a now-stale cached key against a freshly-keyed
    // message.
    const messageKey = await establishInbound(base64ToBytes(kemB64), identity.kemPrivateKey);
    key = { messageKey, peerSigningPublicKey: senderSigningPublicKey };
  } else if (!key) {
    throw new MessageAuthenticityError("missing KEM ciphertext on keying message");
  }

  const signatureB64 = envelope.sig;
  if (typeof signatureB64 !== "string") {
    throw new MessageAuthenticityError("missing signature");
  }
  const plaintext = await openMessage(
    key.messageKey,
    ciphertext,
    nonce,
    base64ToBytes(signatureB64),
    senderSigningPublicKey,
    message.conversation_id,
    message.sender_identity_key_id,
  );
  return { plaintext, key };
}

// ---- Per-conversation key store (localStorage) ----------------------------

function storeKey(convId: string, key: ConversationKeyMaterial): void {
  localStorage.setItem(
    CONV_KEY_PREFIX + convId,
    JSON.stringify({
      messageKey: bytesToBase64(key.messageKey),
      peerSigningPublicKey: bytesToBase64(key.peerSigningPublicKey),
    }),
  );
}

function loadKey(convId: string): ConversationKeyMaterial | null {
  const raw = localStorage.getItem(CONV_KEY_PREFIX + convId);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as { messageKey: string; peerSigningPublicKey: string };
    return {
      messageKey: base64ToBytes(s.messageKey),
      peerSigningPublicKey: base64ToBytes(s.peerSigningPublicKey),
    };
  } catch {
    return null;
  }
}

export const conversationKeyStore = {
  get: loadKey,
  set: storeKey,
  clear(convId: string): void {
    localStorage.removeItem(CONV_KEY_PREFIX + convId);
  },
};