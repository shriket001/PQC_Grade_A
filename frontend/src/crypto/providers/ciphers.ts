/**
 * Grade A: AES-256-GCM AEAD for message and file content, via
 * `@noble/ciphers` (kept alongside the ML-KEM/ML-DSA providers for a
 * consistent, audited, cross-browser implementation rather than relying on
 * SubtleCrypto directly). A fresh random 96-bit nonce is generated per
 * encrypt call.
 */

import { gcm } from "@noble/ciphers/aes";
import type { EncryptedPayload, FileCipher, MessageCipher } from "../interfaces";

const NONCE_LENGTH_BYTES = 12;

function encryptWith(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): EncryptedPayload {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH_BYTES));
  const ciphertext = gcm(key, nonce, associatedData).encrypt(plaintext);
  return { ciphertext, nonce };
}

function decryptWith(
  key: Uint8Array,
  payload: EncryptedPayload,
  associatedData: Uint8Array,
): Uint8Array {
  return gcm(key, payload.nonce, associatedData).decrypt(payload.ciphertext);
}

export const aes256GcmMessageCipher: MessageCipher = {
  async encrypt(key, plaintext, associatedData = new Uint8Array()) {
    return encryptWith(key, plaintext, associatedData);
  },
  async decrypt(key, payload, associatedData = new Uint8Array()) {
    return decryptWith(key, payload, associatedData);
  },
};

export const aes256GcmFileCipher: FileCipher = {
  async encrypt(key, plaintext, associatedData = new Uint8Array()) {
    return encryptWith(key, plaintext, associatedData);
  },
  async decrypt(key, payload, associatedData = new Uint8Array()) {
    return decryptWith(key, payload, associatedData);
  },
};
