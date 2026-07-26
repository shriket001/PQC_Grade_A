/**
 * messagingStore.bootstrap / unlockWithPassword wiring (FR-054 / Phase 5c).
 *
 * The real `unlockIdentity` decision tree (cache → fetch+unwrap → generate+wrap
 * +publish, identity-locked) is exercised in `tests/crypto/vault.test.ts`. These
 * tests mock `@/crypto/vault` and the messaging service so the store can be
 * asserted in isolation: that bootstrap consumes + clears the transient
 * password, sets identityReady, loads conversations, and that a locked identity
 * surfaces `identityLocked` for the unlock prompt.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Hoisted mock controls so the vi.mock factories (which run before the module
// body) can reference them. The IdentityLockedError class is defined here too
// (not as a top-level class) so the hoisted mock factory can access it.
const {
  IdentityLockedError,
  unlockIdentityMock,
  fetchMyWrappedIdentityMock,
  publishIdentityKeyMock,
  listConversationsMock,
} = vi.hoisted(() => {
  // A real class so the store's `instanceof IdentityLockedError` check works.
  class IdentityLockedError extends Error {
    constructor() {
      super("identity is locked — password required to unlock messages");
      this.name = "IdentityLockedError";
    }
  }
  return {
    IdentityLockedError,
    unlockIdentityMock: vi.fn(),
    fetchMyWrappedIdentityMock: vi.fn(),
    publishIdentityKeyMock: vi.fn(),
    listConversationsMock: vi.fn(),
  };
});

vi.mock("@/crypto/vault", () => ({
  IdentityLockedError,
  unlockIdentity: unlockIdentityMock,
}));

vi.mock("@/services/messagingService", async (importActual) => {
  const actual = await importActual<typeof import("@/services/messagingService")>();
  return {
    ...actual,
    fetchMyWrappedIdentity: fetchMyWrappedIdentityMock,
    publishIdentityKey: publishIdentityKeyMock,
    listConversations: listConversationsMock,
  };
});

import { setAccessToken } from "@/services/apiClient";
import { useAuthStore } from "@/store/authStore";
import { __resetDecryptCaches, useMessagingStore } from "@/store/messagingStore";

const futureIso = new Date(Date.now() + 60_000).toISOString();
const PASSWORD = "correct horse battery staple";

const FAKE_IDENTITY = {
  keyId: "key-1",
  deviceLabel: "web",
  signingPublicKey: new Uint8Array([1, 2, 3]),
  signingPrivateKey: new Uint8Array([4, 5, 6]),
  kemPublicKey: new Uint8Array([7, 8, 9]),
  kemPrivateKey: new Uint8Array([10, 11, 12]),
};

function resetStore(): void {
  useMessagingStore.setState({
    identity: null,
    identityReady: false,
    identityLocked: false,
    identityFirstTimeSetup: false,
    conversations: [],
    activeConversationId: null,
    messagesByConversation: {},
    peerUsernameById: {},
    realtimeStatus: "disconnected",
    error: null,
    sending: false,
  });
}

beforeEach(() => {
  localStorage.clear();
  setAccessToken("a.b.c");
  __resetDecryptCaches();
  resetStore();
  unlockIdentityMock.mockReset();
  fetchMyWrappedIdentityMock.mockReset();
  publishIdentityKeyMock.mockReset();
  listConversationsMock.mockReset();
  useAuthStore.getState().signIn({
    userId: "me",
    email: "me@example.com",
    username: "me",
    accessToken: "a.b.c",
    expiresAt: futureIso,
  });
});

afterEach(() => {
  useAuthStore.getState().signOut();
  setAccessToken(null);
  resetStore();
});

describe("messagingStore.bootstrap — identity unlock wiring (FR-054)", () => {
  it("unlocks the identity with the transient password, then clears it and loads conversations", async () => {
    useAuthStore.getState().setPendingUnlockPassword(PASSWORD);
    unlockIdentityMock.mockResolvedValue(FAKE_IDENTITY);
    listConversationsMock.mockResolvedValue([]);

    await useMessagingStore.getState().bootstrap();

    // unlockIdentity received the userId + the transient password + the wired
    // fetch/publish callbacks.
    expect(unlockIdentityMock).toHaveBeenCalledTimes(1);
    const [userId, password, deps] = unlockIdentityMock.mock.calls[0];
    expect(userId).toBe("me");
    expect(password).toBe(PASSWORD);
    expect(deps.fetchWrapped).toBe(fetchMyWrappedIdentityMock);
    expect(deps.publishWrapped).toBe(publishIdentityKeyMock);

    const state = useMessagingStore.getState();
    expect(state.identity).toEqual(FAKE_IDENTITY);
    expect(state.identityReady).toBe(true);
    expect(state.identityLocked).toBe(false);
    // The transient password is consumed + cleared after the handoff.
    expect(useAuthStore.getState().pendingUnlockPassword).toBeNull();
    expect(listConversationsMock).toHaveBeenCalledTimes(1);
  });

  it("surfaces identityLocked (no error) when no password is on hand and no cache exists", async () => {
    // No transient password set; unlockIdentity signals the locked state.
    unlockIdentityMock.mockRejectedValue(new IdentityLockedError());

    await useMessagingStore.getState().bootstrap();

    const state = useMessagingStore.getState();
    expect(state.identityLocked).toBe(true);
    expect(state.identityReady).toBe(false);
    expect(state.error).toBeNull();
    // Conversations are NOT loaded while locked.
    expect(listConversationsMock).not.toHaveBeenCalled();
  });

  it("marks identityFirstTimeSetup when no wrapped identity exists yet (e.g. a brand-new OAuth account)", async () => {
    fetchMyWrappedIdentityMock.mockResolvedValue(null);
    unlockIdentityMock.mockRejectedValue(new IdentityLockedError());

    await useMessagingStore.getState().bootstrap();

    const state = useMessagingStore.getState();
    expect(state.identityLocked).toBe(true);
    expect(state.identityFirstTimeSetup).toBe(true);
  });

  it("does NOT mark identityFirstTimeSetup when a wrapped identity already exists", async () => {
    fetchMyWrappedIdentityMock.mockResolvedValue({
      id: "key-1",
      user_id: "me",
      device_label: "web",
      public_signing_key: "AAAA",
      public_kem_key: "AAAA",
      key_version: 1,
      created_at: futureIso,
      superseded_at: null,
      wrapped_signing_private_key: "ciphertext",
    });
    unlockIdentityMock.mockRejectedValue(new IdentityLockedError());

    await useMessagingStore.getState().bootstrap();

    const state = useMessagingStore.getState();
    expect(state.identityLocked).toBe(true);
    expect(state.identityFirstTimeSetup).toBe(false);
  });

  it("defaults identityFirstTimeSetup to false if the existence check itself fails", async () => {
    fetchMyWrappedIdentityMock.mockRejectedValue(new Error("network error"));
    unlockIdentityMock.mockRejectedValue(new IdentityLockedError());

    await useMessagingStore.getState().bootstrap();

    const state = useMessagingStore.getState();
    expect(state.identityLocked).toBe(true);
    expect(state.identityFirstTimeSetup).toBe(false);
  });

  it("propagates a non-locked bootstrap failure as an error", async () => {
    useAuthStore.getState().setPendingUnlockPassword(PASSWORD);
    unlockIdentityMock.mockRejectedValue(new Error("server is down"));

    await useMessagingStore.getState().bootstrap();

    const state = useMessagingStore.getState();
    expect(state.identityLocked).toBe(false);
    expect(state.identityReady).toBe(false);
    expect(state.error).toBe("server is down");
  });
});

describe("messagingStore.unlockWithPassword — unlock prompt completion (FR-054)", () => {
  it("unlocks with the entered password and clears the locked state", async () => {
    // Put the store into the locked state first.
    useMessagingStore.setState({ identityLocked: true, identityReady: false });
    unlockIdentityMock.mockResolvedValue(FAKE_IDENTITY);
    listConversationsMock.mockResolvedValue([]);

    await useMessagingStore.getState().unlockWithPassword(PASSWORD);

    expect(unlockIdentityMock).toHaveBeenCalledWith(
      "me",
      PASSWORD,
      expect.objectContaining({
        fetchWrapped: fetchMyWrappedIdentityMock,
        publishWrapped: publishIdentityKeyMock,
      }),
    );
    const state = useMessagingStore.getState();
    expect(state.identity).toEqual(FAKE_IDENTITY);
    expect(state.identityReady).toBe(true);
    expect(state.identityLocked).toBe(false);
    expect(useAuthStore.getState().pendingUnlockPassword).toBeNull();
  });

  it("keeps the locked state + sets an error on a wrong password (unwrap failure)", async () => {
    useMessagingStore.setState({ identityLocked: true });
    unlockIdentityMock.mockRejectedValue(new Error("invalid tag"));

    await useMessagingStore.getState().unlockWithPassword("wrong");

    const state = useMessagingStore.getState();
    expect(state.identityLocked).toBe(true);
    expect(state.identityReady).toBe(false);
    expect(state.error).toMatch(/invalid tag|wrong password|could not unlock/i);
  });
});