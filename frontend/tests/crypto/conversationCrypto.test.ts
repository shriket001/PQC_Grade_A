import { describe, expect, it } from "vitest";

import { bytesToBase64, base64ToBytes } from "@/crypto/bytes";
import {
  establishInbound,
  establishOutbound,
  openIncoming,
  openMessage,
  prepareOutgoing,
  sealMessage,
  MessageAuthenticityError,
  conversationKeyStore,
  type PeerPublicKeys,
} from "@/crypto/conversationCrypto";
import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { mlKem768KeyExchangeProvider } from "@/crypto/providers/keyExchangeProvider";
import type { LocalIdentity } from "@/crypto/vault";
import type { MessageResponse } from "@/types/messaging";

async function newIdentity(keyId: string, deviceLabel: string): Promise<LocalIdentity> {
  const signing = await mlDsa65IdentityKeyProvider.generateKeyPair();
  const kem = await mlKem768KeyExchangeProvider.generateKeyPair();
  return {
    keyId,
    deviceLabel,
    signingPublicKey: signing.publicKey,
    signingPrivateKey: signing.privateKey,
    kemPublicKey: kem.publicKey,
    kemPrivateKey: kem.privateKey,
    wrapKey: null,
    wrapKdfSalt: null,
    wrapKdfParams: null,
  };
}

function peerKeysOf(identity: LocalIdentity): PeerPublicKeys {
  return {
    signingPublicKey: identity.signingPublicKey,
    kemPublicKey: identity.kemPublicKey,
  };
}

const CONV = "conv-1";
const ALICE_USER = "user-alice";

describe("conversationCrypto — E2EE round-trip (real @noble post-quantum)", () => {
  it("establishes a shared message key from both sides (ML-KEM-768)", async () => {
    const bob = await newIdentity("bob-key", "bob-dev");
    const { messageKey: aliceKey, kemCiphertext } = await establishOutbound(bob.kemPublicKey);
    const bobKey = await establishInbound(kemCiphertext, bob.kemPrivateKey);
    expect(bobKey).toEqual(aliceKey);
  });

  it("seal + open round-trips plaintext under an established key (ChaCha + ML-DSA)", async () => {
    const alice = await newIdentity("alice-key", "alice-dev");
    const { messageKey } = await establishOutbound(alice.kemPublicKey);
    const plaintext = new TextEncoder().encode("the eagle lands at midnight");
    const sealed = await sealMessage(
      messageKey,
      plaintext,
      alice.signingPrivateKey,
      CONV,
      alice.keyId,
    );
    const recovered = await openMessage(
      messageKey,
      sealed.ciphertext,
      sealed.nonce,
      sealed.signature,
      alice.signingPublicKey,
      CONV,
      alice.keyId,
    );
    expect(new TextDecoder().decode(recovered)).toBe("the eagle lands at midnight");
  });

  it("full prepareOutgoing -> openIncoming cycle decrypts across two identities", async () => {
    const alice = await newIdentity("alice-key", "alice-dev");
    const bob = await newIdentity("bob-key", "bob-dev");

    const plaintext = "hello bob, this is alice";
    const { prepared, key: aliceKey } = await prepareOutgoing(
      CONV,
      peerKeysOf(bob),
      new TextEncoder().encode(plaintext),
      alice,
      null,
    );
    conversationKeyStore.set(CONV, aliceKey);
    expect(prepared.keying).toBe(true);
    expect(typeof prepared.envelope.kem).toBe("string");

    // Build the wire shape the backend would relay as message.new.
    const message: MessageResponse = {
      id: "msg-1",
      conversation_id: CONV,
      sender_id: ALICE_USER,
      sender_identity_key_id: alice.keyId,
      ciphertext: prepared.ciphertextB64,
      envelope: prepared.envelope,
      sent_at: new Date().toISOString(),
    };

    const fetchSenderSigningKey = async (userId: string, keyId: string): Promise<Uint8Array> => {
      expect(userId).toBe(ALICE_USER);
      expect(keyId).toBe(alice.keyId);
      return alice.signingPublicKey;
    };

    const { plaintext: recovered, key: bobKey } = await openIncoming(
      message,
      bob,
      null,
      fetchSenderSigningKey,
    );
    expect(new TextDecoder().decode(recovered)).toBe(plaintext);
    expect(bobKey.messageKey).toEqual(aliceKey.messageKey);
  });

  it("a subsequent message reuses the established key and omits the KEM ciphertext", async () => {
    const alice = await newIdentity("alice-key", "alice-dev");
    const bob = await newIdentity("bob-key", "bob-dev");

    const fetchAlice = async (): Promise<Uint8Array> => alice.signingPublicKey;

    // First (keying) message: alice initiates, bob establishes his inbound key.
    const first = await prepareOutgoing(
      CONV,
      peerKeysOf(bob),
      new TextEncoder().encode("first"),
      alice,
      null,
    );
    expect(first.prepared.keying).toBe(true);
    const firstMsg: MessageResponse = {
      id: "msg-1",
      conversation_id: CONV,
      sender_id: ALICE_USER,
      sender_identity_key_id: alice.keyId,
      ciphertext: first.prepared.ciphertextB64,
      envelope: first.prepared.envelope,
      sent_at: new Date().toISOString(),
    };
    const { plaintext: firstText, key: bobKey } = await openIncoming(firstMsg, bob, null, fetchAlice);
    expect(new TextDecoder().decode(firstText)).toBe("first");

    // Second message: alice reuses her established key (no KEM ciphertext).
    const second = await prepareOutgoing(
      CONV,
      null,
      new TextEncoder().encode("second"),
      alice,
      first.key,
    );
    expect(second.prepared.keying).toBe(false);
    expect(second.prepared.envelope.kem).toBeUndefined();

    const secondMsg: MessageResponse = {
      id: "msg-2",
      conversation_id: CONV,
      sender_id: ALICE_USER,
      sender_identity_key_id: alice.keyId,
      ciphertext: second.prepared.ciphertextB64,
      envelope: second.prepared.envelope,
      sent_at: new Date().toISOString(),
    };
    // Bob reuses the key he established on the first message.
    const { plaintext } = await openIncoming(secondMsg, bob, bobKey, fetchAlice);
    expect(new TextDecoder().decode(plaintext)).toBe("second");
  });

  it("verifies against the SPECIFIC sender key id, not a highest-version key (key-rotation fix)", async () => {
    // Alice has rotated: v1 signed this message, but v2 is now her highest
    // version. Verification must use v1's signing key (matched by key id) —
    // using v2's key would fail with "signature did not verify".
    const aliceV1 = await newIdentity("alice-v1", "alice-dev");
    const aliceV2 = await newIdentity("alice-v2", "alice-dev");
    const bob = await newIdentity("bob-key", "bob-dev");

    const plaintext = "signed by the old key";
    const { prepared, key: aliceKey } = await prepareOutgoing(
      CONV,
      peerKeysOf(bob),
      new TextEncoder().encode(plaintext),
      aliceV1,
      null,
    );
    conversationKeyStore.set(CONV, aliceKey);

    const message: MessageResponse = {
      id: "msg-rot",
      conversation_id: CONV,
      sender_id: ALICE_USER,
      sender_identity_key_id: aliceV1.keyId,
      ciphertext: prepared.ciphertextB64,
      envelope: prepared.envelope,
      sent_at: new Date().toISOString(),
    };

    // Directory-style resolver: returns the signing key matching the requested
    // key id (v1 or v2). openIncoming must ask for aliceV1.keyId.
    const directory = new Map<string, Uint8Array>([
      [aliceV1.keyId, aliceV1.signingPublicKey],
      [aliceV2.keyId, aliceV2.signingPublicKey],
    ]);
    let requestedKeyId = "";
    const fetchSenderSigningKey = async (userId: string, keyId: string): Promise<Uint8Array> => {
      expect(userId).toBe(ALICE_USER);
      requestedKeyId = keyId;
      return directory.get(keyId) ?? new Uint8Array(0);
    };

    const { plaintext: recovered } = await openIncoming(message, bob, null, fetchSenderSigningKey);
    expect(new TextDecoder().decode(recovered)).toBe(plaintext);
    // The resolver was asked for the message's specific key id, not v2's.
    expect(requestedKeyId).toBe(aliceV1.keyId);

    // And a resolver that always returns v2's key fails verification.
    const wrongResolver = async (): Promise<Uint8Array> => aliceV2.signingPublicKey;
    await expect(openIncoming(message, bob, null, wrongResolver)).rejects.toBeInstanceOf(
      MessageAuthenticityError,
    );
  });

  it("rejects a tampered ciphertext (signature no longer verifies)", async () => {
    const alice = await newIdentity("alice-key", "alice-dev");
    const { messageKey } = await establishOutbound(alice.kemPublicKey);
    const sealed = await sealMessage(
      messageKey,
      new TextEncoder().encode("original"),
      alice.signingPrivateKey,
      CONV,
      alice.keyId,
    );
    const tampered = sealed.ciphertext.slice();
    tampered[0] ^= 0xff;
    await expect(
      openMessage(messageKey, tampered, sealed.nonce, sealed.signature, alice.signingPublicKey, CONV, alice.keyId),
    ).rejects.toBeInstanceOf(MessageAuthenticityError);
  });

  it("base64 helpers round-trip arbitrary bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 255, 128, 64, 7]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });
});