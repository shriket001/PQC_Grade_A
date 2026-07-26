/**
 * Group-conversation key management — epoch-based re-keying (US3, T069).
 *
 * Unlike 1:1 (one ML-KEM-768 shared secret reused for the conversation's life,
 * see `conversationCrypto.ts`), a group has no single shared secret between all
 * N members. Instead, each membership change (`conversation.participant_added` /
 * `conversation.participant_removed`, websocket-events.md) bumps a per-group
 * "epoch": whichever client performs the add/remove generates a fresh random
 * 32-byte epoch key and, for every CURRENTLY active member, wraps it under a
 * key derived from an ML-KEM-768 encapsulation to that member's published KEM
 * public key (the same primitive `conversationCrypto`'s 1:1 key establishment
 * uses — mirrored here for N recipients instead of one).
 *
 * This is the crypto-level enforcement behind FR-028 ("a removed participant
 * cannot read messages sent after removal") and Story 3's "a new member reads
 * from the point of joining onward, not retroactively": a member only ever
 * receives the wraps addressed to them for epochs during which they were an
 * active member.
 *   - Removed member: no future epoch ever includes a wrap for them → they
 *     cannot derive the new epoch key → new messages are undecryptable to
 *     them, regardless of whether the server still returns the ciphertext
 *     rows (the server is not the enforcement point — see
 *     `conversation_service.py`'s module docstring).
 *   - Newly-added member: the epoch bump that added them is the first epoch
 *     they ever receive a wrap for; earlier epochs' keys were never
 *     distributed to them and are not recoverable from anything they hold.
 *
 * The key-distribution message travels through the SAME opaque message
 * pipeline as regular content (`POST/WS /conversations/{id}/messages`) — no
 * new server-side schema or migration is needed (Constitution Principle IV,
 * KISS/YAGNI): the backend only ever sees another opaque `ciphertext` +
 * `envelope`, exactly as research.md Decision #1/#15 require. The envelope's
 * `extra: allow` bag carries `epoch` + `keyWraps` (opaque, per-recipient
 * blobs, algorithm-agnostic) instead of the 1:1 envelope's single `kem`/`sig`.
 *
 * All private key material and every plaintext epoch key stay behind this
 * boundary, in the browser only (FR-051/SC-002).
 */

import { aes256GcmMessageCipher } from "@/crypto/providers/ciphers";
import { hkdfSha3256KeyDerivationFunction } from "@/crypto/providers/kdf";
import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { mlKem768KeyExchangeProvider } from "@/crypto/providers/keyExchangeProvider";
import { base64ToBytes, bytesToBase64, concatBytes } from "@/crypto/bytes";
import type { MessageEnvelope } from "@/types/messaging";

const EPOCH_KEY_LENGTH = 32;
const HKDF_WRAP_INFO = new TextEncoder().encode("vayunx/grade-a/group-key-wrap/v1");
const GROUP_KEY_PREFIX = "vayunx.groupkey.";
const GROUP_EPOCH_PREFIX = "vayunx.groupepoch.";

// ---- Epoch key generation + per-recipient wrapping -------------------------

/** A fresh random 32-byte symmetric key for one group epoch. */
export function generateEpochKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(EPOCH_KEY_LENGTH));
}

export interface EpochKeyWrap {
  kemCiphertext: Uint8Array;
  wrappedKey: Uint8Array;
  nonce: Uint8Array;
}

async function deriveWrapKey(sharedSecret: Uint8Array): Promise<Uint8Array> {
  return hkdfSha3256KeyDerivationFunction.derive(sharedSecret, HKDF_WRAP_INFO, EPOCH_KEY_LENGTH);
}

/** Wrap `epochKey` so only the holder of `recipientKemPrivateKey` (matching
 * `recipientKemPublicKey`) can recover it. */
export async function wrapEpochKeyForRecipient(
  epochKey: Uint8Array,
  recipientKemPublicKey: Uint8Array,
): Promise<EpochKeyWrap> {
  const { ciphertext: kemCiphertext, sharedSecret } = await mlKem768KeyExchangeProvider.encapsulate(
    recipientKemPublicKey,
  );
  const wrapKey = await deriveWrapKey(sharedSecret);
  const { ciphertext: wrappedKey, nonce } = await aes256GcmMessageCipher.encrypt(
    wrapKey,
    epochKey,
  );
  return { kemCiphertext, wrappedKey, nonce };
}

/** Recover the epoch key from a wrap addressed to `myKemPrivateKey`. Throws if
 * the wrap was not addressed to this key (AEAD tag will not verify). */
export async function unwrapEpochKey(
  wrap: EpochKeyWrap,
  myKemPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  const sharedSecret = await mlKem768KeyExchangeProvider.decapsulate(
    myKemPrivateKey,
    wrap.kemCiphertext,
  );
  const wrapKey = await deriveWrapKey(sharedSecret);
  return aes256GcmMessageCipher.decrypt(
    wrapKey,
    { ciphertext: wrap.wrappedKey, nonce: wrap.nonce },
    new Uint8Array(),
  );
}

// ---- Key-distribution envelope (wire format) -------------------------------

export interface GroupKeyWrapWire {
  kem: string; // base64 KEM ciphertext
  wrappedKey: string; // base64
  nonce: string; // base64
}

export interface KeyDistribution {
  epoch: number;
  keyWraps: Record<string, GroupKeyWrapWire>; // keyed by recipient identity-key id
}

/** Build the opaque key-distribution material for this envelope's `extra`
 * bag. Carried alongside a normal `MessageEnvelope` shape (alg/nonce/version
 * still apply to the trivial sealed marker content — see `sealGroupMessage`). */
export function buildKeyDistributionExtra(dist: KeyDistribution): {
  epoch: number;
  keyWraps: Record<string, GroupKeyWrapWire>;
} {
  return { epoch: dist.epoch, keyWraps: dist.keyWraps };
}

/** Parse a `MessageEnvelope`'s opaque bag back into a `KeyDistribution`, or
 * null if this envelope does not carry one (a regular chat message). */
export function parseKeyDistributionExtra(envelope: MessageEnvelope): KeyDistribution | null {
  const epoch = envelope.epoch;
  const keyWraps = envelope.keyWraps;
  if (typeof epoch !== "number" || typeof keyWraps !== "object" || keyWraps === null) {
    return null;
  }
  return { epoch, keyWraps: keyWraps as Record<string, GroupKeyWrapWire> };
}

/** Encode one recipient's wrap into the wire (base64) shape. */
export function encodeWrap(wrap: EpochKeyWrap): GroupKeyWrapWire {
  return {
    kem: bytesToBase64(wrap.kemCiphertext),
    wrappedKey: bytesToBase64(wrap.wrappedKey),
    nonce: bytesToBase64(wrap.nonce),
  };
}

export function decodeWrap(wire: GroupKeyWrapWire): EpochKeyWrap {
  return {
    kemCiphertext: base64ToBytes(wire.kem),
    wrappedKey: base64ToBytes(wire.wrappedKey),
    nonce: base64ToBytes(wire.nonce),
  };
}

/**
 * Generate a new epoch key and wrap it for every given recipient. Called by
 * whichever client performs an add/remove (T068 triggers this on
 * `conversation.participant_added`/`participant_removed`).
 */
export async function createAndWrapNewEpoch(
  previousEpoch: number,
  recipients: Array<{ identityKeyId: string; kemPublicKey: Uint8Array }>,
): Promise<{ epoch: number; key: Uint8Array; keyWraps: Record<string, GroupKeyWrapWire> }> {
  const key = generateEpochKey();
  const epoch = previousEpoch + 1;
  const keyWraps: Record<string, GroupKeyWrapWire> = {};
  for (const r of recipients) {
    const wrap = await wrapEpochKeyForRecipient(key, r.kemPublicKey);
    keyWraps[r.identityKeyId] = encodeWrap(wrap);
  }
  return { epoch, key, keyWraps };
}

/** Recover the epoch key addressed to `myIdentityKeyId` from a distribution
 * message, or null if this distribution does not include a wrap for us (e.g.
 * we were removed before this epoch, or this message predates our joining). */
export async function acceptKeyDistribution(
  dist: KeyDistribution,
  myIdentityKeyId: string,
  myKemPrivateKey: Uint8Array,
): Promise<Uint8Array | null> {
  const wire = dist.keyWraps[myIdentityKeyId];
  if (!wire) return null;
  try {
    return await unwrapEpochKey(decodeWrap(wire), myKemPrivateKey);
  } catch {
    // AEAD tag failure — the wrap was not really addressed to this key.
    return null;
  }
}

// ---- Sealing / opening group chat content under an epoch key --------------

function groupAssociatedData(conversationId: string, senderKeyId: string, epoch: number): Uint8Array {
  return new TextEncoder().encode(`${conversationId}|${senderKeyId}|${epoch}`);
}

export interface SealedGroupMessage {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  signature: Uint8Array;
}

/** Encrypt + sign one group message under the current epoch key. Mirrors
 * `conversationCrypto.sealMessage`, with the epoch folded into the AAD so a
 * ciphertext cannot be replayed as if it belonged to a different epoch. */
export async function sealGroupMessage(
  epochKey: Uint8Array,
  plaintext: Uint8Array,
  signingPrivateKey: Uint8Array,
  conversationId: string,
  senderKeyId: string,
  epoch: number,
): Promise<SealedGroupMessage> {
  const aad = groupAssociatedData(conversationId, senderKeyId, epoch);
  const { ciphertext, nonce } = await aes256GcmMessageCipher.encrypt(epochKey, plaintext, aad);
  const signature = await mlDsa65IdentityKeyProvider.sign(
    signingPrivateKey,
    concatBytes(ciphertext, nonce, aad),
  );
  return { ciphertext, nonce, signature };
}

export class GroupMessageAuthenticityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GroupMessageAuthenticityError";
  }
}

/** Verify authorship + decrypt one group message under the epoch key that
 * sealed it (FR-027). Throws `GroupMessageAuthenticityError` on a failed
 * signature. */
export async function openGroupMessage(
  epochKey: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  signature: Uint8Array,
  senderSigningPublicKey: Uint8Array,
  conversationId: string,
  senderKeyId: string,
  epoch: number,
): Promise<Uint8Array> {
  const aad = groupAssociatedData(conversationId, senderKeyId, epoch);
  const valid = await mlDsa65IdentityKeyProvider.verify(
    senderSigningPublicKey,
    concatBytes(ciphertext, nonce, aad),
    signature,
  );
  if (!valid) {
    throw new GroupMessageAuthenticityError("signature did not verify");
  }
  return aes256GcmMessageCipher.decrypt(epochKey, { ciphertext, nonce }, aad);
}

// ---- Per-conversation epoch key store (localStorage) -----------------------

function keyStorageKey(convId: string, epoch: number): string {
  return `${GROUP_KEY_PREFIX}${convId}.${epoch}`;
}

function currentEpochStorageKey(convId: string): string {
  return `${GROUP_EPOCH_PREFIX}${convId}`;
}

export const groupKeyStore = {
  /** Highest epoch this browser holds a key for, or null if none yet. */
  getCurrentEpoch(convId: string): number | null {
    const raw = localStorage.getItem(currentEpochStorageKey(convId));
    if (!raw) return null;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  },

  getKey(convId: string, epoch: number): Uint8Array | null {
    const raw = localStorage.getItem(keyStorageKey(convId, epoch));
    if (!raw) return null;
    try {
      return base64ToBytes(raw);
    } catch {
      return null;
    }
  },

  /** Store a key for `epoch`, bumping the "current epoch" pointer if this is
   * the newest one seen so far. */
  setKey(convId: string, epoch: number, key: Uint8Array): void {
    localStorage.setItem(keyStorageKey(convId, epoch), bytesToBase64(key));
    const current = groupKeyStore.getCurrentEpoch(convId);
    if (current === null || epoch > current) {
      localStorage.setItem(currentEpochStorageKey(convId), String(epoch));
    }
  },

  clear(convId: string): void {
    const current = groupKeyStore.getCurrentEpoch(convId);
    if (current !== null) {
      for (let e = 1; e <= current; e += 1) {
        localStorage.removeItem(keyStorageKey(convId, e));
      }
    }
    localStorage.removeItem(currentEpochStorageKey(convId));
  },
};
