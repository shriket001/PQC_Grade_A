/**
 * Grade A: ML-DSA-65 identity keys (post-quantum signatures, FIPS 204),
 * via `@noble/post-quantum`. Private keys never leave this module boundary
 * unencrypted — callers persist them via the browser's local key storage
 * (IndexedDB, itself encrypted at rest by the platform), never via the
 * backend API client.
 */

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import type { IdentityKeyProvider } from "../interfaces";

export const mlDsa65IdentityKeyProvider: IdentityKeyProvider = {
  async generateKeyPair() {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const keys = ml_dsa65.keygen(seed);
    return { publicKey: keys.publicKey, privateKey: keys.secretKey };
  },

  async sign(privateKey, message) {
    return ml_dsa65.sign(privateKey, message);
  },

  async verify(publicKey, message, signature) {
    return ml_dsa65.verify(publicKey, message, signature);
  },
};
