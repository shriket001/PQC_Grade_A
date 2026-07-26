import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { bytesToBase64 } from "@/crypto/bytes";
import {
  WRAP_ALG,
  deriveWrappingKey,
  parseWrapKdfParams,
  wrapPrivateKey,
} from "@/crypto/identityWrap";
import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { mlKem768KeyExchangeProvider } from "@/crypto/providers/keyExchangeProvider";
import {
  IdentityLockedError,
  clearLocalIdentity,
  loadLocalIdentity,
  storeLocalIdentity,
  unlockIdentity,
  type WrappedPublishInput,
} from "@/crypto/vault";
import type { IdentityKeyResponse } from "@/types/messaging";

// Light Argon2id params for the generate+wrap path so tests stay fast; the
// recover/unwrap path reads params from the record (also light below).
const LIGHT_KDF_PARAMS = "argon2id:t=1:m=4096:p=1";
const PASSWORD = "correct horse battery staple";

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  localStorage.clear();
});

async function generateKeypair() {
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
 * Wrap a keypair exactly as the vault does, returning both the publish input
 * and the underlying pair, so a test can build a wrapped `IdentityKeyResponse`
 * to feed the recover path (or assert on the publish payload).
 */
async function wrapKeypair(password: string, kdfParams = LIGHT_KDF_PARAMS) {
  const pair = await generateKeypair();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const params = parseWrapKdfParams(kdfParams);
  const wrapKey = await deriveWrappingKey(password, salt, params);
  const signingWrapped = await wrapPrivateKey(wrapKey, pair.signingPrivateKey, pair.signingPublicKey);
  const kemWrapped = await wrapPrivateKey(wrapKey, pair.kemPrivateKey, pair.kemPublicKey);
  const combinedNonce = new Uint8Array(24);
  combinedNonce.set(signingWrapped.nonce, 0);
  combinedNonce.set(kemWrapped.nonce, 12);
  const input: WrappedPublishInput = {
    device_label: "web",
    public_signing_key: bytesToBase64(pair.signingPublicKey),
    public_kem_key: bytesToBase64(pair.kemPublicKey),
    wrapped_signing_private_key: bytesToBase64(signingWrapped.ciphertext),
    wrapped_kem_private_key: bytesToBase64(kemWrapped.ciphertext),
    wrap_nonce: bytesToBase64(combinedNonce),
    wrap_kdf_salt: bytesToBase64(salt),
    wrap_kdf_params: kdfParams,
    wrap_alg: WRAP_ALG,
  };
  return { pair, input };
}

function recordFromInput(input: WrappedPublishInput, id = "key-1"): IdentityKeyResponse {
  return {
    id,
    user_id: "user-1",
    device_label: input.device_label,
    public_signing_key: input.public_signing_key,
    public_kem_key: input.public_kem_key,
    key_version: 1,
    created_at: "2026-07-22T00:00:00Z",
    superseded_at: null,
    wrapped_signing_private_key: input.wrapped_signing_private_key,
    wrapped_kem_private_key: input.wrapped_kem_private_key,
    wrap_nonce: input.wrap_nonce,
    wrap_kdf_salt: input.wrap_kdf_salt,
    wrap_kdf_params: input.wrap_kdf_params,
    wrap_alg: input.wrap_alg,
  };
}

describe("vault — unlockIdentity first-login (generate + wrap + publish)", () => {
  it("scopes the persisted identity to the userId and publishes the wrapped pair", async () => {
    const publish = vi.fn().mockResolvedValue({ id: "key-alice" });
    const alice = await unlockIdentity(
      "user-alice",
      PASSWORD,
      { fetchWrapped: vi.fn().mockResolvedValue(null), publishWrapped: publish },
      { kdfParams: LIGHT_KDF_PARAMS },
    );

    expect(alice.keyId).toBe("key-alice");
    expect(loadLocalIdentity("user-alice")?.keyId).toBe("key-alice");
    // Per-user slot, NOT the legacy global key.
    expect(localStorage.getItem("vayunx.identity")).toBeNull();
    expect(localStorage.getItem("vayunx.identity.user-alice")).not.toBeNull();
    expect(publish).toHaveBeenCalledTimes(1);
    // The publish payload carries the complete wrapped set (FR-054 all-or-none).
    const sent = publish.mock.calls[0][0] as WrappedPublishInput;
    expect(sent.wrapped_signing_private_key).toBeTruthy();
    expect(sent.wrapped_kem_private_key).toBeTruthy();
    expect(sent.wrap_nonce).toBeTruthy();
    expect(sent.wrap_kdf_salt).toBeTruthy();
    expect(sent.wrap_kdf_params).toBe(LIGHT_KDF_PARAMS);
    expect(sent.wrap_alg).toBe(WRAP_ALG);
  });

  it("gives each account its own keypair so switching accounts never reuses another user's keyId", async () => {
    const publish = vi
      .fn()
      .mockResolvedValueOnce({ id: "key-alice" })
      .mockResolvedValueOnce({ id: "key-bob" });
    const fetchNull = vi.fn().mockResolvedValue(null);

    const alice = await unlockIdentity(
      "user-alice",
      PASSWORD,
      { fetchWrapped: fetchNull, publishWrapped: publish },
      { kdfParams: LIGHT_KDF_PARAMS },
    );
    const bob = await unlockIdentity(
      "user-bob",
      PASSWORD,
      { fetchWrapped: fetchNull, publishWrapped: publish },
      { kdfParams: LIGHT_KDF_PARAMS },
    );

    expect(alice.keyId).toBe("key-alice");
    expect(bob.keyId).toBe("key-bob");
    expect(alice.signingPublicKey).not.toEqual(bob.signingPublicKey);
    expect(loadLocalIdentity("user-alice")?.keyId).toBe("key-alice");
    expect(loadLocalIdentity("user-bob")?.keyId).toBe("key-bob");
    expect(publish).toHaveBeenCalledTimes(2);
  });

  it("is idempotent per user: a cached identity is reused and never re-published", async () => {
    const publish = vi.fn().mockResolvedValue({ id: "key-alice" });
    const fetchNull = vi.fn().mockResolvedValue(null);
    const deps = { fetchWrapped: fetchNull, publishWrapped: publish };

    const first = await unlockIdentity("user-alice", PASSWORD, deps, {
      kdfParams: LIGHT_KDF_PARAMS,
    });
    // Second call has NO password — but the cache hit makes it unnecessary.
    const second = await unlockIdentity("user-alice", null, deps);

    expect(second.keyId).toBe(first.keyId);
    expect(second.signingPublicKey).toEqual(first.signingPublicKey);
    expect(publish).toHaveBeenCalledTimes(1);
  });
});

describe("vault — unlockIdentity recover (fetch + unwrap)", () => {
  it("recovers the SAME identity from a wrapped record with the password", async () => {
    const { pair, input } = await wrapKeypair(PASSWORD);
    const record = recordFromInput(input, "key-recover");
    const fetchWrapped = vi.fn().mockResolvedValue(record);
    const publish = vi.fn();

    // Simulate a fresh browser: no cached identity, but the password is on hand.
    const recovered = await unlockIdentity(
      "user-1",
      PASSWORD,
      { fetchWrapped, publishWrapped: publish },
    );

    expect(recovered.keyId).toBe("key-recover");
    // The recovered private keys match the originals → all history decrypts.
    expect(recovered.signingPrivateKey).toEqual(pair.signingPrivateKey);
    expect(recovered.kemPrivateKey).toEqual(pair.kemPrivateKey);
    expect(recovered.signingPublicKey).toEqual(pair.signingPublicKey);
    // Recover never re-publishes.
    expect(publish).not.toHaveBeenCalled();
    // And caches locally for refresh.
    expect(loadLocalIdentity("user-1")?.keyId).toBe("key-recover");
  });

  it("a wrong password fails to unwrap (Poly1305 tag mismatch) — no private key leaked", async () => {
    const { input } = await wrapKeypair(PASSWORD);
    const record = recordFromInput(input, "key-recover");
    const fetchWrapped = vi.fn().mockResolvedValue(record);
    const publish = vi.fn();

    await expect(
      unlockIdentity("user-1", "wrong-password", { fetchWrapped, publishWrapped: publish }),
    ).rejects.toThrow();
    expect(publish).not.toHaveBeenCalled();
    expect(loadLocalIdentity("user-1")).toBeNull();
  });

  it("throws IdentityLockedError when no cache and no password is supplied", async () => {
    const fetchWrapped = vi.fn().mockResolvedValue(null);
    const publish = vi.fn();
    await expect(
      unlockIdentity("user-1", null, { fetchWrapped, publishWrapped: publish }),
    ).rejects.toBeInstanceOf(IdentityLockedError);
    // No fetch/publish work was done past the lock check.
    expect(fetchWrapped).not.toHaveBeenCalled();
    expect(publish).not.toHaveBeenCalled();
  });

  it("a pre-cutover chacha20-poly1305 wrapped record is NOT fed to AES-GCM (would throw invalid ghash tag) — it generates a fresh AES-256-GCM identity", async () => {
    // A real pre-cutover account's identity was wrapped with chacha20-poly1305
    // before the 2026-07-26 AES-256-GCM hard cutover. The current cipher cannot
    // unwrap those bytes — feeding them to GCM throws "aes/gcm: invalid ghash
    // tag" (the opaque error the user saw at the unlock prompt). The wrap_alg
    // guard must skip the doomed unwrap and fall through to generate-fresh.
    const chachaRecord: IdentityKeyResponse = {
      id: "key-stale",
      user_id: "user-1",
      device_label: "web",
      // Public keys are irrelevant — the record is never unwrapped.
      public_signing_key: bytesToBase64(crypto.getRandomValues(new Uint8Array(32))),
      public_kem_key: bytesToBase64(crypto.getRandomValues(new Uint8Array(32))),
      key_version: 1,
      created_at: "2026-07-26T12:42:19Z",
      superseded_at: null,
      // Bogus ciphertext: GCM tag verification would fail on these (proving the
      // old code path threw), so the test is a genuine regression guard.
      wrapped_signing_private_key: bytesToBase64(crypto.getRandomValues(new Uint8Array(64))),
      wrapped_kem_private_key: bytesToBase64(crypto.getRandomValues(new Uint8Array(64))),
      wrap_nonce: bytesToBase64(crypto.getRandomValues(new Uint8Array(24))),
      wrap_kdf_salt: bytesToBase64(crypto.getRandomValues(new Uint8Array(16))),
      wrap_kdf_params: LIGHT_KDF_PARAMS,
      wrap_alg: "chacha20-poly1305",
    };
    const fetchWrapped = vi.fn().mockResolvedValue(chachaRecord);
    const publish = vi.fn().mockResolvedValue({ id: "key-fresh" });

    const identity = await unlockIdentity(
      "user-1",
      PASSWORD,
      { fetchWrapped, publishWrapped: publish },
      { kdfParams: LIGHT_KDF_PARAMS },
    );

    // A fresh identity was generated + published under the current cipher; the
    // stale ChaCha20 record was never unwrapped (no throw, no leaked key).
    expect(identity.keyId).toBe("key-fresh");
    expect(publish).toHaveBeenCalledTimes(1);
    expect((publish.mock.calls[0][0] as WrappedPublishInput).wrap_alg).toBe(WRAP_ALG);
    expect(loadLocalIdentity("user-1")?.keyId).toBe("key-fresh");
  });
});

describe("vault — legacy global identity migration", () => {
  it("wraps + publishes the legacy keypair from this browser, preserving history", async () => {
    const legacy = await generateKeypair();
    // Pre-per-user-fix slot (bare key, no `.<userId>` suffix).
    localStorage.setItem(
      "vayunx.identity",
      JSON.stringify({
        keyId: "legacy-key",
        deviceLabel: "web",
        signingPublicKey: bytesToBase64(legacy.signingPublicKey),
        signingPrivateKey: bytesToBase64(legacy.signingPrivateKey),
        kemPublicKey: bytesToBase64(legacy.kemPublicKey),
        kemPrivateKey: bytesToBase64(legacy.kemPrivateKey),
      }),
    );

    const publish = vi.fn().mockResolvedValue({ id: "key-migrated" });
    const recovered = await unlockIdentity(
      "user-1",
      PASSWORD,
      { fetchWrapped: vi.fn().mockResolvedValue(null), publishWrapped: publish },
      { kdfParams: LIGHT_KDF_PARAMS },
    );

    // The SAME keypair is preserved (history encrypted to the old KEM key still
    // decrypts); only the published record id is new.
    expect(recovered.signingPublicKey).toEqual(legacy.signingPublicKey);
    expect(recovered.kemPrivateKey).toEqual(legacy.kemPrivateKey);
    expect(recovered.keyId).toBe("key-migrated");
    // The legacy slot is cleared once the identity is per-user + recoverable.
    expect(localStorage.getItem("vayunx.identity")).toBeNull();
    expect(publish).toHaveBeenCalledTimes(1);
  });
});

describe("vault — storage helpers (per-user scoping)", () => {
  it("storeLocalIdentity round-trips through loadLocalIdentity (private halves intact)", () => {
    const identity = {
      keyId: "manual-key",
      deviceLabel: "web",
      signingPublicKey: new Uint8Array([1, 2, 3]),
      signingPrivateKey: new Uint8Array([4, 5, 6]),
      kemPublicKey: new Uint8Array([7, 8, 9]),
      kemPrivateKey: new Uint8Array([10, 11, 12]),
      wrapKey: null,
      wrapKdfSalt: null,
      wrapKdfParams: null,
    };
    storeLocalIdentity("user-manual", identity);
    const loaded = loadLocalIdentity("user-manual");
    expect(loaded?.keyId).toBe("manual-key");
    expect(Array.from(loaded?.signingPrivateKey ?? [])).toEqual([4, 5, 6]);
    expect(Array.from(loaded?.kemPrivateKey ?? [])).toEqual([10, 11, 12]);
  });

  it("clearLocalIdentity removes only that user's identity", () => {
    const identity = {
      keyId: "k",
      deviceLabel: "web",
      signingPublicKey: new Uint8Array([1]),
      signingPrivateKey: new Uint8Array([2]),
      kemPublicKey: new Uint8Array([3]),
      kemPrivateKey: new Uint8Array([4]),
      wrapKey: null,
      wrapKdfSalt: null,
      wrapKdfParams: null,
    };
    storeLocalIdentity("user-a", identity);
    storeLocalIdentity("user-b", identity);
    clearLocalIdentity("user-a");
    expect(loadLocalIdentity("user-a")).toBeNull();
    expect(loadLocalIdentity("user-b")?.keyId).toBe("k");
  });
});