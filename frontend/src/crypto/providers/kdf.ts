/** Grade A: HKDF-SHA3-256 key derivation, via `@noble/hashes`. */

import { hkdf } from "@noble/hashes/hkdf";
import { sha3_256 } from "@noble/hashes/sha3";
import type { KeyDerivationFunction } from "../interfaces";

export const hkdfSha3256KeyDerivationFunction: KeyDerivationFunction = {
  async derive(sharedSecret, info, length) {
    return hkdf(sha3_256, sharedSecret, undefined, info, length);
  },
};
