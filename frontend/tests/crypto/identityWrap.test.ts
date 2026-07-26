import { describe, expect, it } from "vitest";

import { bytesToBase64 } from "@/crypto/bytes";
import {
  DEFAULT_WRAP_KDF_PARAMS,
  WRAP_ALG,
  deriveWrappingKey,
  parseWrapKdfParams,
  unwrapPrivateKey,
  wrapPrivateKey,
} from "@/crypto/identityWrap";

// Light Argon2id params so the KDF stays fast in tests; the math (HKDF +
// AES-256-GCM + AAD binding) is identical to production params.
const LIGHT = "argon2id:t=1:m=4096:p=1";
const PASSWORD = "correct horse battery staple";
const WRONG = "wrong password";

async function derive(password: string, salt: Uint8Array, params = LIGHT) {
  return deriveWrappingKey(password, salt, parseWrapKdfParams(params));
}

describe("identityWrap — parseWrapKdfParams", () => {
  it("parses the default production params", () => {
    expect(parseWrapKdfParams(DEFAULT_WRAP_KDF_PARAMS)).toEqual({
      timeCost: 3,
      memoryCost: 65536,
      parallelism: 4,
    });
  });

  it("rejects a non-argon2id algorithm", () => {
    expect(() => parseWrapKdfParams("argon2id:t=3:m=65536:p=4")).not.toThrow();
    expect(() => parseWrapKdfParams("scrypt:n=16384:r=8:p=1")).toThrow();
  });

  it("rejects missing or non-positive fields", () => {
    expect(() => parseWrapKdfParams("argon2id:t=3:m=65536")).toThrow();
    expect(() => parseWrapKdfParams("argon2id:t=0:m=65536:p=4")).toThrow();
    expect(() => parseWrapKdfParams("argon2id:t=3:m=-1:p=4")).toThrow();
    expect(() => parseWrapKdfParams("argon2id:t=3:m=65536:p=4:q=9")).toThrow();
  });
});

describe("identityWrap — wrap/unwrap round-trip", () => {
  it("round-trips a private key when the password + public key match", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await derive(PASSWORD, salt);
    const priv = crypto.getRandomValues(new Uint8Array(64));
    const pub = crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapPrivateKey(wrapKey, priv, pub);
    const unwrapped = await unwrapPrivateKey(wrapKey, wrapped, pub);

    expect(unwrapped).toEqual(priv);
    // The nonce is the expected 12 bytes.
    expect(wrapped.nonce.byteLength).toBe(12);
  });

  it("fails to unwrap with the wrong password (tag mismatch)", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await derive(PASSWORD, salt);
    const wrongKey = await derive(WRONG, salt);
    const priv = crypto.getRandomValues(new Uint8Array(64));
    const pub = crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapPrivateKey(wrapKey, priv, pub);
    await expect(unwrapPrivateKey(wrongKey, wrapped, pub)).rejects.toThrow();
  });

  it("fails to unwrap against a swapped (mismatched) public key — AAD binding", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await derive(PASSWORD, salt);
    const priv = crypto.getRandomValues(new Uint8Array(64));
    const pub = crypto.getRandomValues(new Uint8Array(32));
    const otherPub = crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapPrivateKey(wrapKey, priv, pub);
    // Unwrapping with the right key but the wrong AAD (public key) must fail —
    // this is the substitution-resistance guarantee.
    await expect(unwrapPrivateKey(wrapKey, wrapped, otherPub)).rejects.toThrow();
  });

  it("derives a deterministic wrapping key for the same password + salt + params", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const a = await derive(PASSWORD, salt);
    const b = await derive(PASSWORD, salt);
    expect(a).toEqual(b);
    expect(a.byteLength).toBe(32);
    // A different salt yields a different key.
    const c = await derive(PASSWORD, crypto.getRandomValues(new Uint8Array(16)));
    expect(c).not.toEqual(a);
  });

  it("exposes the production wrap-alg + default params constants", () => {
    expect(WRAP_ALG).toBe("aes-256-gcm");
    expect(DEFAULT_WRAP_KDF_PARAMS).toBe("argon2id:t=3:m=65536:p=4");
    // Sanity: base64 of a 32-byte key is 44 chars (wire format used by vault).
    expect(bytesToBase64(new Uint8Array(32))).toHaveLength(44);
  });
});