/**
 * Grade A: ML-KEM-768 key exchange (post-quantum KEM, FIPS 203),
 * via `@noble/post-quantum`.
 */

import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import type { KeyExchangeProvider } from "../interfaces";

export const mlKem768KeyExchangeProvider: KeyExchangeProvider = {
  async generateKeyPair() {
    const seed = crypto.getRandomValues(new Uint8Array(64));
    const keys = ml_kem768.keygen(seed);
    return { publicKey: keys.publicKey, privateKey: keys.secretKey };
  },

  async encapsulate(peerPublicKey) {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(peerPublicKey);
    return { ciphertext: cipherText, sharedSecret };
  },

  async decapsulate(privateKey, ciphertext) {
    return ml_kem768.decapsulate(ciphertext, privateKey);
  },
};
