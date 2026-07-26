import { describe, expect, it } from "vitest";

import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { mlKem768KeyExchangeProvider } from "@/crypto/providers/keyExchangeProvider";
import {
  GroupMessageAuthenticityError,
  acceptKeyDistribution,
  createAndWrapNewEpoch,
  decodeWrap,
  encodeWrap,
  generateEpochKey,
  groupKeyStore,
  openGroupMessage,
  parseKeyDistributionExtra,
  buildKeyDistributionExtra,
  sealGroupMessage,
  unwrapEpochKey,
  wrapEpochKeyForRecipient,
} from "@/crypto/providers/groupKeyManager";
import type { MessageEnvelope } from "@/types/messaging";

interface Member {
  identityKeyId: string;
  signingPublicKey: Uint8Array;
  signingPrivateKey: Uint8Array;
  kemPublicKey: Uint8Array;
  kemPrivateKey: Uint8Array;
}

async function newMember(identityKeyId: string): Promise<Member> {
  const signing = await mlDsa65IdentityKeyProvider.generateKeyPair();
  const kem = await mlKem768KeyExchangeProvider.generateKeyPair();
  return {
    identityKeyId,
    signingPublicKey: signing.publicKey,
    signingPrivateKey: signing.privateKey,
    kemPublicKey: kem.publicKey,
    kemPrivateKey: kem.privateKey,
  };
}

const CONV = "group-conv-1";

describe("groupKeyManager — epoch-based group re-keying (real @noble post-quantum)", () => {
  it("wraps and unwraps an epoch key for a recipient (ML-KEM-768 + AES-256-GCM)", async () => {
    const bob = await newMember("bob-key");
    const epochKey = generateEpochKey();
    const wrap = await wrapEpochKeyForRecipient(epochKey, bob.kemPublicKey);
    const recovered = await unwrapEpochKey(wrap, bob.kemPrivateKey);
    expect(recovered).toEqual(epochKey);
  });

  it("a recipient without a matching private key cannot unwrap", async () => {
    const bob = await newMember("bob-key");
    const stranger = await newMember("stranger-key");
    const epochKey = generateEpochKey();
    const wrap = await wrapEpochKeyForRecipient(epochKey, bob.kemPublicKey);
    await expect(unwrapEpochKey(wrap, stranger.kemPrivateKey)).rejects.toBeTruthy();
  });

  it("createAndWrapNewEpoch distributes the same key to every active recipient", async () => {
    const alice = await newMember("alice-key");
    const bob = await newMember("bob-key");
    const carol = await newMember("carol-key");

    const { epoch, key, keyWraps } = await createAndWrapNewEpoch(0, [
      { identityKeyId: alice.identityKeyId, kemPublicKey: alice.kemPublicKey },
      { identityKeyId: bob.identityKeyId, kemPublicKey: bob.kemPublicKey },
      { identityKeyId: carol.identityKeyId, kemPublicKey: carol.kemPublicKey },
    ]);
    expect(epoch).toBe(1);

    for (const member of [alice, bob, carol]) {
      const wire = keyWraps[member.identityKeyId];
      expect(wire).toBeDefined();
      const recovered = await unwrapEpochKey(decodeWrap(wire), member.kemPrivateKey);
      expect(recovered).toEqual(key);
    }
  });

  it("round-trips a key-distribution envelope through the opaque extra bag", async () => {
    const alice = await newMember("alice-key");
    const { epoch, keyWraps } = await createAndWrapNewEpoch(3, [
      { identityKeyId: alice.identityKeyId, kemPublicKey: alice.kemPublicKey },
    ]);
    const extra = buildKeyDistributionExtra({ epoch, keyWraps });
    const envelope: MessageEnvelope = {
      alg: "aes-256-gcm",
      nonce: "AAAAAAAAAAAAAAAA",
      version: 1,
      ...extra,
    };
    const parsed = parseKeyDistributionExtra(envelope);
    expect(parsed).not.toBeNull();
    expect(parsed?.epoch).toBe(4);
    expect(Object.keys(parsed?.keyWraps ?? {})).toEqual(["alice-key"]);
  });

  it("a regular chat message's envelope does not parse as a key distribution", () => {
    const envelope: MessageEnvelope = {
      alg: "aes-256-gcm",
      nonce: "AAAAAAAAAAAAAAAA",
      version: 1,
      sig: "c2ln",
    };
    expect(parseKeyDistributionExtra(envelope)).toBeNull();
  });

  it("seal + open round-trips group content under the epoch key", async () => {
    const alice = await newMember("alice-key");
    const epochKey = generateEpochKey();
    const plaintext = new TextEncoder().encode("hello group, epoch 1");

    const sealed = await sealGroupMessage(
      epochKey,
      plaintext,
      alice.signingPrivateKey,
      CONV,
      alice.identityKeyId,
      1,
    );
    const recovered = await openGroupMessage(
      epochKey,
      sealed.ciphertext,
      sealed.nonce,
      sealed.signature,
      alice.signingPublicKey,
      CONV,
      alice.identityKeyId,
      1,
    );
    expect(new TextDecoder().decode(recovered)).toBe("hello group, epoch 1");
  });

  it("a message sealed under epoch N does not open under epoch N+1's key (AAD binds the epoch)", async () => {
    const alice = await newMember("alice-key");
    const epoch1Key = generateEpochKey();
    const epoch2Key = generateEpochKey();
    const plaintext = new TextEncoder().encode("epoch-bound content");

    const sealed = await sealGroupMessage(
      epoch1Key,
      plaintext,
      alice.signingPrivateKey,
      CONV,
      alice.identityKeyId,
      1,
    );
    // Wrong epoch number in the AAD, even with the right key, must fail.
    await expect(
      openGroupMessage(
        epoch1Key,
        sealed.ciphertext,
        sealed.nonce,
        sealed.signature,
        alice.signingPublicKey,
        CONV,
        alice.identityKeyId,
        2,
      ),
    ).rejects.toBeTruthy();
    // Right epoch number, wrong key, must also fail.
    await expect(
      openGroupMessage(
        epoch2Key,
        sealed.ciphertext,
        sealed.nonce,
        sealed.signature,
        alice.signingPublicKey,
        CONV,
        alice.identityKeyId,
        1,
      ),
    ).rejects.toBeTruthy();
  });

  it("rejects a tampered group message (signature no longer verifies)", async () => {
    const alice = await newMember("alice-key");
    const epochKey = generateEpochKey();
    const sealed = await sealGroupMessage(
      epochKey,
      new TextEncoder().encode("original"),
      alice.signingPrivateKey,
      CONV,
      alice.identityKeyId,
      1,
    );
    const tampered = sealed.ciphertext.slice();
    tampered[0] ^= 0xff;
    await expect(
      openGroupMessage(
        epochKey,
        tampered,
        sealed.nonce,
        sealed.signature,
        alice.signingPublicKey,
        CONV,
        alice.identityKeyId,
        1,
      ),
    ).rejects.toBeInstanceOf(GroupMessageAuthenticityError);
  });

  it("FR-028: a removed member gets no wrap in the next epoch and cannot decrypt it", async () => {
    const alice = await newMember("alice-key");
    const bob = await newMember("bob-key");

    // Epoch 1: alice + bob.
    const first = await createAndWrapNewEpoch(0, [
      { identityKeyId: alice.identityKeyId, kemPublicKey: alice.kemPublicKey },
      { identityKeyId: bob.identityKeyId, kemPublicKey: bob.kemPublicKey },
    ]);
    expect(await acceptKeyDistribution(first, bob.identityKeyId, bob.kemPrivateKey)).toEqual(
      first.key,
    );

    // Bob is removed; epoch 2 is distributed to alice only.
    const second = await createAndWrapNewEpoch(first.epoch, [
      { identityKeyId: alice.identityKeyId, kemPublicKey: alice.kemPublicKey },
    ]);
    expect(second.epoch).toBe(2);
    // Bob has no wrap for epoch 2 at all — acceptKeyDistribution returns null,
    // not a decryption of the wrong key.
    const bobAttempt = await acceptKeyDistribution(second, bob.identityKeyId, bob.kemPrivateKey);
    expect(bobAttempt).toBeNull();

    // A message sealed under epoch 2 is therefore unreadable to bob: he has no
    // key material to even attempt `openGroupMessage` with.
    const plaintext = new TextEncoder().encode("this is after bob's removal");
    const sealed = await sealGroupMessage(
      second.key,
      plaintext,
      alice.signingPrivateKey,
      CONV,
      alice.identityKeyId,
      2,
    );
    // Even if bob somehow obtained the ciphertext (server still relays it —
    // FR-051 means the server can't tell), he has no key to open it with.
    expect(groupKeyStore.getKey(CONV, 2)).toBeNull();
    void sealed; // (documented, not decryptable without the key — nothing to assert further)
  });

  it("groupKeyStore persists per-epoch keys and tracks the current epoch", () => {
    const conv = "store-conv";
    groupKeyStore.clear(conv);
    expect(groupKeyStore.getCurrentEpoch(conv)).toBeNull();

    const k1 = generateEpochKey();
    groupKeyStore.setKey(conv, 1, k1);
    expect(groupKeyStore.getCurrentEpoch(conv)).toBe(1);
    expect(groupKeyStore.getKey(conv, 1)).toEqual(k1);

    const k2 = generateEpochKey();
    groupKeyStore.setKey(conv, 2, k2);
    expect(groupKeyStore.getCurrentEpoch(conv)).toBe(2);
    // Older epoch's key is still retrievable (needed to read old messages).
    expect(groupKeyStore.getKey(conv, 1)).toEqual(k1);
    expect(groupKeyStore.getKey(conv, 2)).toEqual(k2);

    groupKeyStore.clear(conv);
    expect(groupKeyStore.getCurrentEpoch(conv)).toBeNull();
    expect(groupKeyStore.getKey(conv, 1)).toBeNull();
    expect(groupKeyStore.getKey(conv, 2)).toBeNull();
  });

  it("encodeWrap/decodeWrap round-trips an EpochKeyWrap through base64", async () => {
    const bob = await newMember("bob-key");
    const epochKey = generateEpochKey();
    const wrap = await wrapEpochKeyForRecipient(epochKey, bob.kemPublicKey);
    const wire = encodeWrap(wrap);
    const decoded = decodeWrap(wire);
    expect(decoded.kemCiphertext).toEqual(wrap.kemCiphertext);
    expect(decoded.wrappedKey).toEqual(wrap.wrappedKey);
    expect(decoded.nonce).toEqual(wrap.nonce);
  });
});
