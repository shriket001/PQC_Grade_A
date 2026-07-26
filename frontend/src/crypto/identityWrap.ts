/**
 * Identity wrapping — cross-device recoverable identity (FR-054, Phase 5c).
 *
 * The user's ML-DSA-65 signing + ML-KEM-768 KEM *private* keys are wrapped
 * (encrypted) under a key derived from the user's password, so the wrapped
 * blobs can be stored on the backend and unwrapped on any browser that knows
 * the password. This is the Proton-style recoverability tradeoff: the backend
 * stores only ciphertext + wrapped keys + public keys + wrap parameters — it
 * never receives the password-derived wrapping key, the raw password (beyond
 * the existing /auth/login), or plaintext. FR-051/SC-002 preserved.
 *
 * Wrap key derivation (mirrors the Grade-A suite: Argon2id + HKDF-SHA3-256):
 *   wrapKey = HKDF-SHA3-256(Argon2id(password, salt, params),
 *                            info="vayunx/grade-a/identity-wrap/v1", 32)
 *
 * Wrapping (AES-256-GCM, AAD = the matching *public* key):
 *   AAD binds each wrapped private key to its public key, so a swapped public
 *   key (or a wrapped private key from a different keypair) fails to unwrap —
 *   substitution resistance.
 *
 * All crypto here is browser-side; the server only persists and relays the
 * opaque wrapped blobs (it never runs Argon2id for wrapping).
 */

import { argon2id } from "hash-wasm";
import { aes256GcmMessageCipher } from "@/crypto/providers/ciphers";
import { hkdfSha3256KeyDerivationFunction } from "@/crypto/providers/kdf";

/** Wrap-algorithm identifier persisted per record (only one value today). */
export const WRAP_ALG = "aes-256-gcm";

/**
 * Default browser-tuned Argon2id parameters, stored per-record so any browser
 * can reproduce the KDF. Matches the backend's argon2-cffi library defaults
 * (t=3, m=65536 KiB = 64 MiB, p=4) for cross-suite consistency.
 */
export const DEFAULT_WRAP_KDF_PARAMS = "argon2id:t=3:m=65536:p=4";

const WRAP_KDF_INFO = new TextEncoder().encode("vayunx/grade-a/identity-wrap/v1");
const WRAP_KEY_LENGTH = 32;

export interface WrapKdfParams {
  /** Iterations / time cost. */
  timeCost: number;
  /** Memory cost in KiB. */
  memoryCost: number;
  /** Parallelism (lanes). */
  parallelism: number;
}

/**
 * Parse a persisted KDF-params string of the form `"argon2id:t=3:m=65536:p=4"`.
 * Throws if the algorithm is not `argon2id` or any field is missing/invalid.
 */
export function parseWrapKdfParams(params: string): WrapKdfParams {
  const [alg, ...rest] = params.split(":");
  if (alg !== "argon2id") {
    throw new Error(`unsupported wrap KDF algorithm: ${alg}`);
  }
  const map = new Map<string, number>();
  for (const part of rest) {
    const [key, val] = part.split("=");
    if (!key || val === undefined) throw new Error(`malformed wrap KDF param: ${part}`);
    if (key !== "t" && key !== "m" && key !== "p") {
      throw new Error(`unknown wrap KDF param: ${key}`);
    }
    const n = Number(val);
    if (!Number.isInteger(n) || n <= 0) throw new Error(`invalid wrap KDF value: ${part}`);
    map.set(key, n);
  }
  const timeCost = map.get("t");
  const memoryCost = map.get("m");
  const parallelism = map.get("p");
  if (timeCost === undefined || memoryCost === undefined || parallelism === undefined) {
    throw new Error(`incomplete wrap KDF params: ${params}`);
  }
  return { timeCost, memoryCost, parallelism };
}

/**
 * Derive the 32-byte wrapping key from the user's password + the per-record
 * salt + KDF parameters. The salt is stored on the backend alongside the
 * wrapped blobs, so any browser that knows the password reproduces this key.
 */
export async function deriveWrappingKey(
  password: string,
  salt: Uint8Array,
  params: WrapKdfParams,
): Promise<Uint8Array> {
  const passwordBytes = new TextEncoder().encode(password);
  const argon2Output = await argon2id({
    password: passwordBytes,
    salt,
    parallelism: params.parallelism,
    memorySize: params.memoryCost,
    iterations: params.timeCost,
    hashLength: WRAP_KEY_LENGTH,
    outputType: "binary",
  });
  return hkdfSha3256KeyDerivationFunction.derive(argon2Output, WRAP_KDF_INFO, WRAP_KEY_LENGTH);
}

/**
 * Wrap a private key with AES-256-GCM under `wrapKey`, binding it to its
 * matching `publicKey` via AAD. Returns the opaque ciphertext + nonce to persist.
 */
export async function wrapPrivateKey(
  wrapKey: Uint8Array,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  return aes256GcmMessageCipher.encrypt(wrapKey, privateKey, publicKey);
}

/**
 * Unwrap a wrapped private key. Fails (throws) if `wrapKey` is wrong OR if
 * `publicKey` is not the matching public key for the wrapped private key — the
 * AAD mismatch makes the Poly1305 tag fail to verify. That is the substitution
 * resistance + wrong-password guarantee.
 */
export async function unwrapPrivateKey(
  wrapKey: Uint8Array,
  payload: { ciphertext: Uint8Array; nonce: Uint8Array },
  publicKey: Uint8Array,
): Promise<Uint8Array> {
  return aes256GcmMessageCipher.decrypt(wrapKey, payload, publicKey);
}