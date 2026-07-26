/**
 * Identity vault — the browser's store of the local user's own ML-DSA-65 signing
 * and ML-KEM-768 key-exchange keypairs, plus the backend-issued identity-key id.
 *
 * FR-054 (cross-device recovery): the private keypair is **wrapped** (encrypted)
 * under a password-derived key and stored on the backend, so the same identity
 * can be unwrapped on any browser that knows the password (WhatsApp-style). The
 * backend only ever receives the *public* halves plus the opaque wrapped blobs +
 * wrap parameters — never the wrapping key, raw password (beyond /auth/login),
 * or plaintext (FR-051/SC-002 preserved).
 *
 * The unwrapped identity is cached per-user in `localStorage`
 * (`vayunx.identity.<userId>`) for same-tab refresh convenience (mirrors the
 * dev-convenience trade-off made for the refresh token in `authStore`; US10
 * hardens both to IndexedDB-at-rest). The identity is scoped PER USER — every
 * account gets its own keypair, and the backend-issued `keyId` is bound to that
 * account. Without this scoping, logging in as user B on a browser that
 * previously held user A's identity would reuse A's `keyId`, so B would never
 * publish their own keys (this caused the "peer has no published identity keys"
 * send failure when switching accounts).
 */

import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { mlKem768KeyExchangeProvider } from "@/crypto/providers/keyExchangeProvider";
import { base64ToBytes, bytesToBase64 } from "@/crypto/bytes";
import {
  DEFAULT_WRAP_KDF_PARAMS,
  WRAP_ALG,
  deriveWrappingKey,
  parseWrapKdfParams,
  unwrapPrivateKey,
  wrapPrivateKey,
} from "@/crypto/identityWrap";
import type { IdentityKeyResponse } from "@/types/messaging";

const STORAGE_PREFIX = "vayunx.identity";
// Pre-per-user-fix slot (bare key, no `.<userId>` suffix). Read once during the
// legacy migration so a user's existing history on this browser is preserved.
const LEGACY_GLOBAL_KEY = "vayunx.identity";
const NONCE_LENGTH_BYTES = 12;
const WRAP_SALT_LENGTH = 16;

function storageKeyFor(userId: string): string {
  return `${STORAGE_PREFIX}.${userId}`;
}

/**
 * Raised by `unlockIdentity` when no cached identity exists and no password was
 * supplied. The caller surfaces an "unlock messages" prompt and re-runs
 * `unlockIdentity` with the password once entered.
 */
export class IdentityLockedError extends Error {
  constructor() {
    super("identity is locked — password required to unlock messages");
    this.name = "IdentityLockedError";
  }
}

export interface LocalIdentity {
  /** Backend identity-key record id for the published public pair. */
  keyId: string;
  deviceLabel: string;
  signingPublicKey: Uint8Array;
  signingPrivateKey: Uint8Array;
  kemPublicKey: Uint8Array;
  kemPrivateKey: Uint8Array;
  /**
   * The password-derived wrapping key (Argon2id -> HKDF-SHA3-256), retained
   * for the session so a NEWLY-established conversation key can be backed up
   * (wrapped + pushed to the server, see `conversationKeyBackup.ts`) without
   * re-prompting for the password on every send. Cached alongside the private
   * keys themselves (same same-tab-refresh convenience tradeoff already made
   * for them — see the module docstring). Null for an identity cached before
   * this field existed, until the next password unlock repopulates it.
   */
  wrapKey: Uint8Array | null;
  /** The salt + KDF params `wrapKey` was derived with — pushed alongside every
   * conversation-key backup so any browser can reproduce `wrapKey` from the
   * password later. Null iff `wrapKey` is null. */
  wrapKdfSalt: Uint8Array | null;
  wrapKdfParams: string | null;
}

interface SerializedIdentity {
  keyId: string;
  deviceLabel: string;
  signingPublicKey: string;
  signingPrivateKey: string;
  kemPublicKey: string;
  kemPrivateKey: string;
  wrapKey?: string;
  wrapKdfSalt?: string;
  wrapKdfParams?: string;
}

/** The public + private halves of a keypair, independent of any storage id. */
interface Keypair {
  signingPublicKey: Uint8Array;
  signingPrivateKey: Uint8Array;
  kemPublicKey: Uint8Array;
  kemPrivateKey: Uint8Array;
}

/** Publish input carrying the wrapped private material (FR-054 all-or-none set). */
export interface WrappedPublishInput {
  device_label: string;
  public_signing_key: string; // base64
  public_kem_key: string; // base64
  wrapped_signing_private_key: string; // base64
  wrapped_kem_private_key: string; // base64
  wrap_nonce: string; // base64 (signingNonce(12) || kemNonce(12))
  wrap_kdf_salt: string; // base64
  wrap_kdf_params: string;
  wrap_alg: string;
}

export type PublishWrappedFn = (input: WrappedPublishInput) => Promise<{ id: string }>;
export type FetchWrappedFn = () => Promise<IdentityKeyResponse | null>;

/** Optional `unlockIdentity` tuning (prod uses the defaults). */
export interface UnlockOptions {
  /** Device label attached to the published key (default "web"). */
  deviceLabel?: string;
  /**
   * KDF-params string for the generate+wrap path (default
   * `DEFAULT_WRAP_KDF_PARAMS`). The recover/unwrap path always uses the params
   * stored on the record. Exposed so tests can use light Argon2id params.
   */
  kdfParams?: string;
}

function serialize(identity: LocalIdentity): SerializedIdentity {
  return {
    keyId: identity.keyId,
    deviceLabel: identity.deviceLabel,
    signingPublicKey: bytesToBase64(identity.signingPublicKey),
    signingPrivateKey: bytesToBase64(identity.signingPrivateKey),
    kemPublicKey: bytesToBase64(identity.kemPublicKey),
    kemPrivateKey: bytesToBase64(identity.kemPrivateKey),
    wrapKey: identity.wrapKey ? bytesToBase64(identity.wrapKey) : undefined,
    wrapKdfSalt: identity.wrapKdfSalt ? bytesToBase64(identity.wrapKdfSalt) : undefined,
    wrapKdfParams: identity.wrapKdfParams ?? undefined,
  };
}

function deserialize(s: SerializedIdentity): LocalIdentity {
  return {
    keyId: s.keyId,
    deviceLabel: s.deviceLabel,
    signingPublicKey: base64ToBytes(s.signingPublicKey),
    signingPrivateKey: base64ToBytes(s.signingPrivateKey),
    kemPublicKey: base64ToBytes(s.kemPublicKey),
    kemPrivateKey: base64ToBytes(s.kemPrivateKey),
    // Legacy cache entries (written before conversation-key backup existed)
    // have none of these — null until the next password unlock repopulates them.
    wrapKey: s.wrapKey ? base64ToBytes(s.wrapKey) : null,
    wrapKdfSalt: s.wrapKdfSalt ? base64ToBytes(s.wrapKdfSalt) : null,
    wrapKdfParams: s.wrapKdfParams ?? null,
  };
}

/** Read the persisted local identity for `userId`, or null if none yet. */
export function loadLocalIdentity(userId: string): LocalIdentity | null {
  const raw = localStorage.getItem(storageKeyFor(userId));
  if (!raw) return null;
  try {
    return deserialize(JSON.parse(raw) as SerializedIdentity);
  } catch {
    return null;
  }
}

export function storeLocalIdentity(userId: string, identity: LocalIdentity): void {
  localStorage.setItem(storageKeyFor(userId), JSON.stringify(serialize(identity)));
}

export function clearLocalIdentity(userId: string): void {
  localStorage.removeItem(storageKeyFor(userId));
}

/** Generate a fresh ML-DSA-65 + ML-KEM-768 keypair. */
async function generateKeypair(): Promise<Keypair> {
  const signing = await mlDsa65IdentityKeyProvider.generateKeyPair();
  const kem = await mlKem768KeyExchangeProvider.generateKeyPair();
  return {
    signingPublicKey: signing.publicKey,
    signingPrivateKey: signing.privateKey,
    kemPublicKey: kem.publicKey,
    kemPrivateKey: kem.privateKey,
  };
}

/**
 * Wrap both private keys under the (already-derived) `wrapKey`, binding each to
 * its matching public key via AAD. Returns the publish input plus the combined
 * nonce. The two wrap calls each draw a fresh random nonce; both are stored in
 * the single `wrap_nonce` field as `signingNonce(12) || kemNonce(12)` (24 bytes,
 * opaque to the server) — so neither nonce is reused under the same key.
 */
async function wrapKeypairForPublish(
  wrapKey: Uint8Array,
  salt: Uint8Array,
  pair: Keypair,
  deviceLabel: string,
  kdfParams: string,
): Promise<WrappedPublishInput> {
  const signingWrapped = await wrapPrivateKey(
    wrapKey,
    pair.signingPrivateKey,
    pair.signingPublicKey,
  );
  const kemWrapped = await wrapPrivateKey(wrapKey, pair.kemPrivateKey, pair.kemPublicKey);

  const combinedNonce = new Uint8Array(NONCE_LENGTH_BYTES * 2);
  combinedNonce.set(signingWrapped.nonce, 0);
  combinedNonce.set(kemWrapped.nonce, NONCE_LENGTH_BYTES);

  return {
    device_label: deviceLabel,
    public_signing_key: bytesToBase64(pair.signingPublicKey),
    public_kem_key: bytesToBase64(pair.kemPublicKey),
    wrapped_signing_private_key: bytesToBase64(signingWrapped.ciphertext),
    wrapped_kem_private_key: bytesToBase64(kemWrapped.ciphertext),
    wrap_nonce: bytesToBase64(combinedNonce),
    wrap_kdf_salt: bytesToBase64(salt),
    wrap_kdf_params: kdfParams,
    wrap_alg: WRAP_ALG,
  };
}

/** Unwrap both private keys from an auth-scoped wrapped identity record, given
 * the already-derived `wrapKey`. */
async function unwrapKeypairFromRecord(
  wrapKey: Uint8Array,
  record: IdentityKeyResponse,
): Promise<Keypair> {
  if (
    !record.wrapped_signing_private_key ||
    !record.wrapped_kem_private_key ||
    !record.wrap_nonce ||
    !record.wrap_kdf_salt ||
    !record.wrap_kdf_params
  ) {
    throw new Error("identity record has no wrapped private material");
  }
  const signingPub = base64ToBytes(record.public_signing_key);
  const kemPub = base64ToBytes(record.public_kem_key);
  const nonceBlob = base64ToBytes(record.wrap_nonce);
  const signingNonce = nonceBlob.subarray(0, NONCE_LENGTH_BYTES);
  const kemNonce = nonceBlob.subarray(NONCE_LENGTH_BYTES, NONCE_LENGTH_BYTES * 2);

  const signingPrivateKey = await unwrapPrivateKey(
    wrapKey,
    { ciphertext: base64ToBytes(record.wrapped_signing_private_key), nonce: signingNonce },
    signingPub,
  );
  const kemPrivateKey = await unwrapPrivateKey(
    wrapKey,
    { ciphertext: base64ToBytes(record.wrapped_kem_private_key), nonce: kemNonce },
    kemPub,
  );
  return {
    signingPublicKey: signingPub,
    signingPrivateKey,
    kemPublicKey: kemPub,
    kemPrivateKey,
  };
}

/** Read the legacy pre-per-user-fix global identity, if this browser holds it. */
function readLegacyGlobalKeypair(): Keypair | null {
  const raw = localStorage.getItem(LEGACY_GLOBAL_KEY);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as SerializedIdentity;
    return {
      signingPublicKey: base64ToBytes(s.signingPublicKey),
      signingPrivateKey: base64ToBytes(s.signingPrivateKey),
      kemPublicKey: base64ToBytes(s.kemPublicKey),
      kemPrivateKey: base64ToBytes(s.kemPrivateKey),
    };
  } catch {
    return null;
  }
}

function clearLegacyGlobalIdentity(): void {
  localStorage.removeItem(LEGACY_GLOBAL_KEY);
}

/**
 * Bootstrap decision tree (replaces the old `ensureLocalIdentity`):
 *
 * 1. `loadLocalIdentity(userId)` hit (same-browser refresh) → use it. No
 *    password needed.
 * 2. No cache + no password → throw `IdentityLockedError`; the caller prompts
 *    for the password and re-runs.
 * 3. With a password, `fetchWrapped()`:
 *    a. Record with wrapped material → derive the wrap key from the password +
 *       the stored salt/params, unwrap, cache, return (the WhatsApp-style
 *       cross-device recovery path — the SAME identity is restored, so all
 *       history decrypts and all signatures verify).
 *    b. No record, or a legacy record without wrapped material → take the
 *       legacy global plaintext identity from this browser if present
 *       (preserves this browser's existing history), else generate a fresh
 *       keypair; wrap it under the password and publish so any browser can
 *       recover it later. Cache the unwrapped identity locally and return.
 *
 * Callers pass `fetchWrapped`/`publishWrapped` so this module stays free of a
 * direct apiClient dependency (testable in isolation).
 */
export async function unlockIdentity(
  userId: string,
  password: string | null,
  deps: { fetchWrapped: FetchWrappedFn; publishWrapped: PublishWrappedFn },
  options: UnlockOptions = {},
): Promise<LocalIdentity> {
  const deviceLabel = options.deviceLabel ?? "web";
  const kdfParams = options.kdfParams ?? DEFAULT_WRAP_KDF_PARAMS;
  // 1. Cache hit — same-browser refresh, no password required.
  const cached = loadLocalIdentity(userId);
  if (cached) return cached;

  // 2. No cache + no transient password → locked; surface the unlock prompt.
  if (!password) throw new IdentityLockedError();

  // 3. Auth-scoped fetch of the caller's active identity (null = first login).
  const record = await deps.fetchWrapped();

  let pair: Keypair;
  let keyId: string;
  let wrapKey: Uint8Array;
  let wrapKdfSalt: Uint8Array;
  let wrapKdfParamsUsed: string;

  if (
    record &&
    record.wrapped_signing_private_key &&
    record.wrapped_kem_private_key &&
    record.wrap_nonce &&
    record.wrap_kdf_salt &&
    record.wrap_kdf_params &&
    // Only attempt an AES-256-GCM unwrap when the record was actually wrapped
    // with this cipher. The ChaCha20-Poly1305 -> AES-256-GCM hard cutover
    // (2026-07-26) left pre-cutover accounts with chacha20-poly1305 wrapped
    // identities that the current cipher CANNOT unwrap — feeding them to GCM
    // throws an opaque "aes/gcm: invalid ghash tag" (wrong-tag) error that
    // reads like a wrong password. Such a record is unrecoverable under the
    // current cipher, so fall through to 3b (generate a fresh identity under
    // AES-256-GCM) instead of attempting a doomed unwrap. This self-heals any
    // pre-cutover account on its next password unlock. (The accepted hard-
    // cutover tradeoff: history encrypted under the old identity is lost.)
    record.wrap_alg === WRAP_ALG
  ) {
    // 3a. Recover the existing identity by unwrapping with the password.
    wrapKdfSalt = base64ToBytes(record.wrap_kdf_salt);
    wrapKdfParamsUsed = record.wrap_kdf_params;
    wrapKey = await deriveWrappingKey(password, wrapKdfSalt, parseWrapKdfParams(wrapKdfParamsUsed));
    pair = await unwrapKeypairFromRecord(wrapKey, record);
    keyId = record.id;
  } else {
    // 3b. First login, or a legacy record that was never wrapped: prefer the
    //     legacy global plaintext identity on this browser (history preserved),
    //     else generate a fresh keypair. Wrap + publish so the identity becomes
    //     recoverable on other browsers going forward.
    pair = readLegacyGlobalKeypair() ?? (await generateKeypair());
    wrapKdfSalt = crypto.getRandomValues(new Uint8Array(WRAP_SALT_LENGTH));
    wrapKdfParamsUsed = kdfParams;
    wrapKey = await deriveWrappingKey(password, wrapKdfSalt, parseWrapKdfParams(kdfParams));
    const input = await wrapKeypairForPublish(wrapKey, wrapKdfSalt, pair, deviceLabel, kdfParams);
    const published = await deps.publishWrapped(input);
    keyId = published.id;
    // The legacy slot is now superseded by the per-user, server-recoverable
    // identity; clear it so it is not re-read on a future bootstrap.
    clearLegacyGlobalIdentity();
  }

  const identity: LocalIdentity = {
    keyId,
    deviceLabel: record?.device_label ?? deviceLabel,
    signingPublicKey: pair.signingPublicKey,
    signingPrivateKey: pair.signingPrivateKey,
    kemPublicKey: pair.kemPublicKey,
    kemPrivateKey: pair.kemPrivateKey,
    wrapKey,
    wrapKdfSalt,
    wrapKdfParams: wrapKdfParamsUsed,
  };
  storeLocalIdentity(userId, identity);
  return identity;
}