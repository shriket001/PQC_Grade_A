/**
 * Client-side crypto isolation boundary — the frontend half of Constitution
 * Principle I / spec FR-051. Message/file plaintext and all private key
 * material are generated, encrypted, and decrypted ONLY behind these
 * interfaces, in the browser. Nothing outside `src/crypto/` may perform a
 * cryptographic operation directly, and no private key or plaintext content
 * may be sent to the backend API client (`src/services/apiClient.ts`).
 */

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface IdentityKeyProvider {
  generateKeyPair(): Promise<KeyPair>;
  sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface KeyExchangeProvider {
  generateKeyPair(): Promise<KeyPair>;
  /** Initiating party: returns { ciphertext, sharedSecret } for a peer's public key. */
  encapsulate(
    peerPublicKey: Uint8Array,
  ): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }>;
  /** Receiving party: recovers the shared secret from the initiator's ciphertext. */
  decapsulate(privateKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
}

export interface KeyDerivationFunction {
  derive(sharedSecret: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
}

export interface EncryptedPayload {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

export interface MessageCipher {
  encrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
    associatedData?: Uint8Array,
  ): Promise<EncryptedPayload>;
  decrypt(
    key: Uint8Array,
    payload: EncryptedPayload,
    associatedData?: Uint8Array,
  ): Promise<Uint8Array>;
}

export interface FileCipher {
  encrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
    associatedData?: Uint8Array,
  ): Promise<EncryptedPayload>;
  decrypt(
    key: Uint8Array,
    payload: EncryptedPayload,
    associatedData?: Uint8Array,
  ): Promise<Uint8Array>;
}
