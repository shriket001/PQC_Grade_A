import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { bytesToBase64 } from "@/crypto/bytes";
import {
  acceptKeyDistribution,
  groupKeyStore,
  parseKeyDistributionExtra,
} from "@/crypto/providers/groupKeyManager";
import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { mlKem768KeyExchangeProvider } from "@/crypto/providers/keyExchangeProvider";
import { setAccessToken } from "@/services/apiClient";
import { useAuthStore } from "@/store/authStore";
import {
  __resetDecryptCaches,
  decryptConversationLog,
  getDecryptedText,
  getDecryptError,
  useMessagingStore,
} from "@/store/messagingStore";
import type { LocalIdentity } from "@/crypto/vault";
import type { ConversationResponse, MessageResponse } from "@/types/messaging";

const futureIso = new Date(Date.now() + 60_000).toISOString();

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

function resetStore(): void {
  useMessagingStore.setState({
    identity: null,
    identityReady: false,
    identityLocked: false,
    conversations: [],
    activeConversationId: null,
    messagesByConversation: {},
    peerUsernameById: {},
    lastMessagePreviewByConversation: {},
    realtimeStatus: "disconnected",
    error: null,
    sending: false,
  });
}

const fetchMock = vi.fn();

beforeEach(() => {
  localStorage.clear();
  fetchMock.mockReset();
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  setAccessToken("a.b.c");
  __resetDecryptCaches();
  resetStore();
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

describe("messagingStore.startConversation — username-driven direct chat (FR-052/FR-053)", () => {
  it("resolves the username via /users/search then creates the conversation with the resolved id", async () => {
    const conv = {
      id: "conv-1",
      type: "direct",
      name: null,
      created_by: "me",
      created_at: "2030-01-01T00:00:00Z",
      participants: [
        { user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" },
        { user_id: "bob-id", role: null, joined_at: "2030-01-01T00:00:00Z" },
      ],
    };
    fetchMock.mockImplementation(async (url: string) => {
      if (url.startsWith("/api/v1/users/search")) {
        return jsonResponse(200, [
          { id: "bob-id", username: "bob", display_name: "bob" },
        ]);
      }
      if (url === "/api/v1/conversations") {
        return jsonResponse(201, conv);
      }
      return jsonResponse(404, { error_code: "unknown_error", message: "x" });
    });

    const id = await useMessagingStore.getState().startConversation("bob");

    expect(id).toBe("conv-1");
    const state = useMessagingStore.getState();
    expect(state.conversations[0].id).toBe("conv-1");
    expect(state.activeConversationId).toBe("conv-1");
    // The resolved handle is cached so the rail/thread can show it.
    expect(state.peerUsernameById["bob-id"]).toBe("bob");

    // The create call used the resolved peer id — no out-of-band copying.
    const createCall = fetchMock.mock.calls.find((c) => c[0] === "/api/v1/conversations");
    expect(createCall).toBeDefined();
    expect(JSON.parse(createCall![1].body as string)).toEqual({
      type: "direct",
      participant_user_ids: ["bob-id"],
      name: null,
    });
  });

  it("matches the handle case-insensitively", async () => {
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(200, [{ id: "bob-id", username: "bob", display_name: "bob" }]),
    );
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse(201, {
        id: "conv-2",
        type: "direct",
        name: null,
        created_by: "me",
        created_at: "2030-01-01T00:00:00Z",
        participants: [{ user_id: "bob-id", role: null, joined_at: "2030-01-01T00:00:00Z" }],
      }),
    );

    const id = await useMessagingStore.getState().startConversation("BOB");
    expect(id).toBe("conv-2");
  });

  it("returns null and sets an error when no user matches the username", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, []));

    const id = await useMessagingStore.getState().startConversation("nobody");

    expect(id).toBeNull();
    const state = useMessagingStore.getState();
    expect(state.conversations).toEqual([]);
    expect(state.error).toMatch(/No user found/i);
  });

  it("rejects an empty handle without hitting the network", async () => {
    const id = await useMessagingStore.getState().startConversation("   ");
    expect(id).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(useMessagingStore.getState().error).toMatch(/Enter a username/i);
  });
});

describe("messagingStore.deleteConversation — removes the chat + local state (FR-055)", () => {
  it("calls DELETE /conversations/{id}, drops the conversation, clears its messages, and deselects when active", async () => {
    useMessagingStore.setState({
      conversations: [
        {
          id: "conv-a",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [
            { user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" },
            { user_id: "bob-id", role: null, joined_at: "2030-01-01T00:00:00Z" },
          ],
        },
        {
          id: "conv-b",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [{ user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" }],
        },
      ],
      activeConversationId: "conv-a",
      messagesByConversation: { "conv-a": [], "conv-b": [] },
    });

    fetchMock.mockResolvedValue(jsonResponse(204, null));

    const ok = await useMessagingStore.getState().deleteConversation("conv-a");

    expect(ok).toBe(true);
    const state = useMessagingStore.getState();
    expect(state.conversations.map((c) => c.id)).toEqual(["conv-b"]);
    expect(state.messagesByConversation["conv-a"]).toBeUndefined();
    expect(state.activeConversationId).toBeNull();
    // The DELETE hit the right path.
    const deleteCall = fetchMock.mock.calls.find(
      (c) => typeof c[0] === "string" && (c[0] as string).endsWith("/conversations/conv-a"),
    );
    expect(deleteCall).toBeDefined();
    expect((deleteCall![1] as RequestInit).method).toBe("DELETE");
  });

  it("keeps the active selection when a different conversation is deleted", async () => {
    useMessagingStore.setState({
      conversations: [
        {
          id: "conv-a",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [{ user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" }],
        },
        {
          id: "conv-b",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [{ user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" }],
        },
      ],
      activeConversationId: "conv-b",
      messagesByConversation: {},
    });

    fetchMock.mockResolvedValue(jsonResponse(204, null));

    await useMessagingStore.getState().deleteConversation("conv-a");

    expect(useMessagingStore.getState().activeConversationId).toBe("conv-b");
  });

  it("sets an error and returns false when the server rejects the delete", async () => {
    useMessagingStore.setState({
      conversations: [
        {
          id: "conv-a",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [{ user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" }],
        },
      ],
      activeConversationId: "conv-a",
    });

    fetchMock.mockResolvedValue(
      jsonResponse(403, { error_code: "not_participant", message: "not a participant" }),
    );

    const ok = await useMessagingStore.getState().deleteConversation("conv-a");

    expect(ok).toBe(false);
    const state = useMessagingStore.getState();
    // Nothing removed locally on failure.
    expect(state.conversations.map((c) => c.id)).toEqual(["conv-a"]);
    expect(state.activeConversationId).toBe("conv-a");
    expect(state.error).toMatch(/not a participant/i);
  });
});

describe("messagingStore — Phase 5e dedup / ordering / realtime refresh (FR-056/057/058)", () => {
  it("startConversation reuses an existing conversation id from the server (get-or-create) — no duplicate", async () => {
    useMessagingStore.setState({
      conversations: [
        {
          id: "conv-1",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [
            { user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" },
            { user_id: "bob-id", role: null, joined_at: "2030-01-01T00:00:00Z" },
          ],
        },
      ],
    });
    fetchMock.mockImplementation(async (url: string) => {
      if (url.startsWith("/api/v1/users/search")) {
        return jsonResponse(200, [{ id: "bob-id", username: "bob", display_name: "bob" }]);
      }
      if (url === "/api/v1/conversations") {
        // Server get-or-create returns the SAME conversation id.
        return jsonResponse(201, {
          id: "conv-1",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [
            { user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" },
            { user_id: "bob-id", role: null, joined_at: "2030-01-01T00:00:00Z" },
          ],
        });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const id = await useMessagingStore.getState().startConversation("bob");

    expect(id).toBe("conv-1");
    const state = useMessagingStore.getState();
    // Exactly one entry — the reused conversation, not a duplicate.
    expect(state.conversations.filter((c) => c.id === "conv-1")).toHaveLength(1);
    expect(state.activeConversationId).toBe("conv-1");
  });

  it("sorts the rail newest-first by last_message_at (nulls last) after starting a new chat", async () => {
    useMessagingStore.setState({
      conversations: [
        {
          id: "conv-active",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          last_message_at: "2030-01-05T00:00:00Z",
          participants: [
            { user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" },
            { user_id: "zoe-id", role: null, joined_at: "2030-01-01T00:00:00Z" },
          ],
        },
      ],
    });
    fetchMock.mockImplementation(async (url: string) => {
      if (url.startsWith("/api/v1/users/search")) {
        return jsonResponse(200, [{ id: "carol-id", username: "carol", display_name: "carol" }]);
      }
      if (url === "/api/v1/conversations") {
        // A brand-new conversation with NO messages → null last_message_at.
        return jsonResponse(201, {
          id: "conv-new",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-09T00:00:00Z",
          participants: [
            { user_id: "me", role: null, joined_at: "2030-01-09T00:00:00Z" },
            { user_id: "carol-id", role: null, joined_at: "2030-01-09T00:00:00Z" },
          ],
        });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const id = await useMessagingStore.getState().startConversation("carol");
    expect(id).toBe("conv-new");

    // The conversation with a recent message stays first (nulls last); the new
    // empty chat sorts after it despite a newer created_at.
    const state = useMessagingStore.getState();
    expect(state.conversations.map((c) => c.id)).toEqual(["conv-active", "conv-new"]);
    expect(state.activeConversationId).toBe("conv-new");
  });

  it("ingestRealtimeMessage refreshes the conversation list when the message is for an unknown conversation (FR-057)", async () => {
    // A real-ish identity shape is required so ingest does not bail out; the
    // actual decryption is never reached — the sender's identity key lookup is
    // mocked to 404, so openIncoming throws and the ingest error path runs.
    useMessagingStore.setState({
      identity: {
        keyId: "key-1",
        deviceLabel: "dev",
        signingPublicKey: new Uint8Array(32),
        signingPrivateKey: new Uint8Array(64),
        kemPublicKey: new Uint8Array(1184),
        kemPrivateKey: new Uint8Array(2400),
        wrapKey: null,
        wrapKdfSalt: null,
        wrapKdfParams: null,
      },
      conversations: [],
    });
    let conversationsCalled = 0;
    fetchMock.mockImplementation(async (url: string) => {
      if (url === "/api/v1/conversations") {
        conversationsCalled += 1;
        return jsonResponse(200, []);
      }
      // Sender signing-key directory lookup → not found → openIncoming throws.
      if (url.includes("/identity-keys")) {
        return jsonResponse(404, { error_code: "not_found", message: "no keys" });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    await useMessagingStore.getState().ingestRealtimeMessage({
      conversation_id: "conv-foreign",
      message_id: "msg-x",
      sender_id: "bob-id",
      sender_identity_key_id: "key-1",
      ciphertext: "AAA",
      envelope: { alg: "aes-256-gcm", nonce: "AAA", version: 1 },
      sent_at: "2030-01-09T12:00:00Z",
    });

    // The unknown conversation triggered a list refresh (FR-057).
    expect(conversationsCalled).toBeGreaterThanOrEqual(1);
    // The ciphertext record was still appended to the thread either way.
    const state = useMessagingStore.getState();
    expect(state.messagesByConversation["conv-foreign"]).toHaveLength(1);
    expect(state.messagesByConversation["conv-foreign"][0].id).toBe("msg-x");
  });
});

describe("messagingStore — re-decrypting your own sent keying message after a refresh", () => {
  it("does not misinterpret its own envelope.kem as something to decapsulate", async () => {
    // Regression test: the FIRST message in a 1:1 conversation carries
    // envelope.kem (the KEM ciphertext encapsulated against the PEER's public
    // key). Re-decrypting that same message later from history — as happens
    // on every page refresh, since the in-memory plaintext cache is wiped —
    // must reuse the locally-cached message key rather than trying to
    // decapsulate a ciphertext only the PEER's private key can open. Before
    // the fix, this always failed with "invalid tag".
    const me = await meIdentity();
    useMessagingStore.setState({ identity: me });
    const bob = await newFakeMember("bob-id", "bob");
    useMessagingStore.setState({
      conversations: [
        {
          id: "conv-1",
          type: "direct",
          name: null,
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [
            { user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" },
            { user_id: bob.userId, role: null, joined_at: "2030-01-01T00:00:00Z" },
          ],
        },
      ],
    });

    let stored: MessageResponseLike | null = null;
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === `/api/v1/users/${bob.userId}/identity-keys`) {
        return jsonResponse(200, identityKeysResponseFor(bob));
      }
      if (url === "/api/v1/conversations/conv-1/messages" && init?.method === "POST") {
        const body = JSON.parse(init.body as string) as {
          ciphertext: string;
          envelope: Record<string, unknown>;
        };
        stored = {
          id: "msg-1",
          conversation_id: "conv-1",
          sender_id: "me",
          sender_identity_key_id: "me-key",
          ciphertext: body.ciphertext,
          envelope: body.envelope,
          sent_at: "2030-01-01T00:00:01Z",
        };
        return jsonResponse(201, stored);
      }
      if (url.startsWith("/api/v1/conversations/conv-1/messages") && (!init || !init.method || init.method === "GET")) {
        return jsonResponse(200, { messages: stored ? [stored] : [], next_cursor: null });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    useMessagingStore.setState({ activeConversationId: "conv-1" });
    await useMessagingStore.getState().sendOutgoing("hello bob");
    expect(stored).not.toBeNull();
    expect((stored as unknown as MessageResponseLike).envelope.kem).toBeTruthy();

    // Simulate a browser refresh: the in-memory plaintext cache is gone, and
    // the conversation's message log is re-fetched + re-decrypted from
    // scratch — but the conversation key in localStorage survives (a refresh
    // does not clear it, only clearing browser storage would).
    __resetDecryptCaches();
    useMessagingStore.setState({ messagesByConversation: {} });

    await useMessagingStore.getState().selectConversation("conv-1");

    expect(getDecryptError("msg-1")).toBeNull();
    expect(getDecryptedText("msg-1")).toBe("hello bob");
  });
});

// ---------------------------------------------------------------------------
// US3 (Phase 5): group messaging — epoch-based re-keying end-to-end via the
// store, exercising real ML-KEM-768/ML-DSA-65 (@noble/post-quantum).
// ---------------------------------------------------------------------------

interface MessageResponseLike {
  id: string;
  conversation_id: string;
  sender_id: string;
  sender_identity_key_id: string;
  ciphertext: string;
  envelope: Record<string, unknown>;
  sent_at: string;
}

interface FakeMember {
  userId: string;
  username: string;
  identityKeyId: string;
  signingPublicKey: Uint8Array;
  kemPublicKey: Uint8Array;
  kemPrivateKey: Uint8Array;
}

async function newFakeMember(userId: string, username: string): Promise<FakeMember> {
  const signing = await mlDsa65IdentityKeyProvider.generateKeyPair();
  const kem = await mlKem768KeyExchangeProvider.generateKeyPair();
  return {
    userId,
    username,
    identityKeyId: `${userId}-key`,
    signingPublicKey: signing.publicKey,
    kemPublicKey: kem.publicKey,
    kemPrivateKey: kem.privateKey,
  };
}

function identityKeysResponseFor(member: FakeMember): unknown[] {
  return [
    {
      id: member.identityKeyId,
      user_id: member.userId,
      device_label: "dev",
      public_signing_key: bytesToBase64(member.signingPublicKey),
      public_kem_key: bytesToBase64(member.kemPublicKey),
      key_version: 1,
      created_at: "2030-01-01T00:00:00Z",
      superseded_at: null,
    },
  ];
}

async function meIdentity(): Promise<LocalIdentity> {
  const signing = await mlDsa65IdentityKeyProvider.generateKeyPair();
  const kem = await mlKem768KeyExchangeProvider.generateKeyPair();
  return {
    keyId: "me-key",
    deviceLabel: "dev",
    signingPublicKey: signing.publicKey,
    signingPrivateKey: signing.privateKey,
    kemPublicKey: kem.publicKey,
    kemPrivateKey: kem.privateKey,
    wrapKey: null,
    wrapKdfSalt: null,
    wrapKdfParams: null,
  };
}

describe("messagingStore — group messaging (US3, FR-024/027/028)", () => {
  it("startGroup creates the group and distributes epoch 1 wrapped for every other member", async () => {
    const me = await meIdentity();
    useMessagingStore.setState({ identity: me });
    const bob = await newFakeMember("bob-id", "bob");

    let sentBody: { ciphertext: string; envelope: Record<string, unknown> } | null = null;
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/v1/users/search")) {
        return jsonResponse(200, [{ id: bob.userId, username: bob.username, display_name: bob.username }]);
      }
      if (url === `/api/v1/users/${bob.userId}/identity-keys`) {
        return jsonResponse(200, identityKeysResponseFor(bob));
      }
      if (url === "/api/v1/conversations" && init?.method === "POST") {
        return jsonResponse(201, {
          id: "grp-1",
          type: "group",
          name: "Team",
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [
            { user_id: "me", role: "group_admin", joined_at: "2030-01-01T00:00:00Z" },
            { user_id: bob.userId, role: "member", joined_at: "2030-01-01T00:00:00Z" },
          ],
        });
      }
      if (url === "/api/v1/conversations/grp-1/messages" && init?.method === "POST") {
        sentBody = JSON.parse(init.body as string);
        return jsonResponse(201, {
          id: "msg-dist-1",
          conversation_id: "grp-1",
          sender_id: "me",
          sender_identity_key_id: "me-key",
          ciphertext: sentBody!.ciphertext,
          envelope: sentBody!.envelope,
          sent_at: "2030-01-01T00:00:01Z",
        });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const id = await useMessagingStore.getState().startGroup("Team", ["bob"]);

    expect(id).toBe("grp-1");
    const state = useMessagingStore.getState();
    expect(state.conversations.find((c) => c.id === "grp-1")?.type).toBe("group");
    expect(groupKeyStore.getCurrentEpoch("grp-1")).toBe(1);

    expect(sentBody).not.toBeNull();
    const envelope = sentBody!.envelope;
    expect(envelope.epoch).toBe(1);
    const keyWraps = envelope.keyWraps as Record<string, unknown>;
    expect(Object.keys(keyWraps)).toEqual([bob.identityKeyId]);

    // Bob independently derives the SAME epoch key from his wrap.
    const dist = parseKeyDistributionExtra(envelope as never);
    const bobKey = await acceptKeyDistribution(dist!, bob.identityKeyId, bob.kemPrivateKey);
    expect(bobKey).toEqual(groupKeyStore.getKey("grp-1", 1));
  });

  it("startGroup fails BEFORE creating anything server-side when a member has no published identity keys (no zombie group)", async () => {
    // Regression test: previously the group was created on the server FIRST,
    // and only then did it try to resolve each member's identity key to wrap
    // epoch 1 for them. If a member (e.g. "carol") had never signed in and so
    // had no published keys, that step threw AFTER the group already existed
    // server-side — leaving a group with no epoch key ever established. Every
    // member (including the creator) would then hit "this group's encryption
    // key hasn't been established on this device yet" the moment they tried
    // to open it, with no way to recover. The fix resolves every member's
    // identity key BEFORE calling POST /conversations at all.
    const me = await meIdentity();
    useMessagingStore.setState({ identity: me });

    let createConversationCalled = false;
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/v1/users/search")) {
        return jsonResponse(200, [{ id: "carol-id", username: "carol", display_name: "carol" }]);
      }
      if (url === "/api/v1/users/carol-id/identity-keys") {
        // Carol has never signed in — no published keys yet.
        return jsonResponse(200, []);
      }
      if (url === "/api/v1/conversations" && init?.method === "POST") {
        createConversationCalled = true;
        return jsonResponse(201, {
          id: "grp-zombie",
          type: "group",
          name: "Team",
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [],
        });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const id = await useMessagingStore.getState().startGroup("Team", ["carol"]);

    expect(id).toBeNull();
    // The group must never have been created server-side.
    expect(createConversationCalled).toBe(false);
    expect(useMessagingStore.getState().error).toContain("carol");
    expect(useMessagingStore.getState().conversations).toHaveLength(0);
  });

  it("addGroupMember rekeys to a new epoch that includes the newly-added member", async () => {
    const me = await meIdentity();
    groupKeyStore.setKey("grp-2", 1, new Uint8Array(32).fill(7));
    useMessagingStore.setState({
      identity: me,
      conversations: [
        {
          id: "grp-2",
          type: "group",
          name: "Team",
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [
            { user_id: "me", role: "group_admin", joined_at: "2030-01-01T00:00:00Z" },
            { user_id: "bob-id", role: "member", joined_at: "2030-01-01T00:00:00Z" },
          ],
        },
      ],
    });
    const bob = await newFakeMember("bob-id", "bob");
    const dave = await newFakeMember("dave-id", "dave");

    let sentEnvelope: Record<string, unknown> | null = null;
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/v1/users/search")) {
        return jsonResponse(200, [{ id: dave.userId, username: dave.username, display_name: dave.username }]);
      }
      if (url === `/api/v1/users/${bob.userId}/identity-keys`) {
        return jsonResponse(200, identityKeysResponseFor(bob));
      }
      if (url === `/api/v1/users/${dave.userId}/identity-keys`) {
        return jsonResponse(200, identityKeysResponseFor(dave));
      }
      if (url === "/api/v1/conversations/grp-2/participants" && init?.method === "POST") {
        return jsonResponse(201, { user_id: dave.userId, role: "member", joined_at: "2030-01-02T00:00:00Z" });
      }
      if (url === "/api/v1/conversations" && (!init || init.method === "GET")) {
        return jsonResponse(200, [
          {
            id: "grp-2",
            type: "group",
            name: "Team",
            created_by: "me",
            created_at: "2030-01-01T00:00:00Z",
            participants: [
              { user_id: "me", role: "group_admin", joined_at: "2030-01-01T00:00:00Z" },
              { user_id: bob.userId, role: "member", joined_at: "2030-01-01T00:00:00Z" },
              { user_id: dave.userId, role: "member", joined_at: "2030-01-02T00:00:00Z" },
            ],
          },
        ]);
      }
      if (url === "/api/v1/conversations/grp-2/messages" && init?.method === "POST") {
        const body = JSON.parse(init.body as string);
        sentEnvelope = body.envelope;
        return jsonResponse(201, {
          id: "msg-dist-2",
          conversation_id: "grp-2",
          sender_id: "me",
          sender_identity_key_id: "me-key",
          ciphertext: body.ciphertext,
          envelope: body.envelope,
          sent_at: "2030-01-02T00:00:01Z",
        });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const ok = await useMessagingStore.getState().addGroupMember("grp-2", "dave");

    expect(ok).toBe(true);
    expect(groupKeyStore.getCurrentEpoch("grp-2")).toBe(2);
    expect(sentEnvelope).not.toBeNull();
    const keyWraps = sentEnvelope!.keyWraps as Record<string, unknown>;
    // Both the pre-existing member and the newly-added one get the new epoch.
    expect(new Set(Object.keys(keyWraps))).toEqual(
      new Set([bob.identityKeyId, dave.identityKeyId]),
    );
  });

  it("removeGroupMember rekeys to a new epoch that EXCLUDES the removed member (FR-028)", async () => {
    const me = await meIdentity();
    groupKeyStore.setKey("grp-3", 1, new Uint8Array(32).fill(9));
    useMessagingStore.setState({
      identity: me,
      conversations: [
        {
          id: "grp-3",
          type: "group",
          name: "Team",
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [
            { user_id: "me", role: "group_admin", joined_at: "2030-01-01T00:00:00Z" },
            { user_id: "bob-id", role: "member", joined_at: "2030-01-01T00:00:00Z" },
            { user_id: "carol-id", role: "member", joined_at: "2030-01-01T00:00:00Z" },
          ],
        },
      ],
    });
    const carol = await newFakeMember("carol-id", "carol");

    let sentEnvelope: Record<string, unknown> | null = null;
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === "/api/v1/conversations/grp-3/participants/bob-id" && init?.method === "DELETE") {
        return { ok: true, status: 204, headers: new Headers() } as Response;
      }
      if (url === `/api/v1/users/${carol.userId}/identity-keys`) {
        return jsonResponse(200, identityKeysResponseFor(carol));
      }
      if (url === "/api/v1/conversations" && (!init || init.method === "GET")) {
        return jsonResponse(200, [
          {
            id: "grp-3",
            type: "group",
            name: "Team",
            created_by: "me",
            created_at: "2030-01-01T00:00:00Z",
            participants: [
              { user_id: "me", role: "group_admin", joined_at: "2030-01-01T00:00:00Z" },
              { user_id: carol.userId, role: "member", joined_at: "2030-01-01T00:00:00Z" },
            ],
          },
        ]);
      }
      if (url === "/api/v1/conversations/grp-3/messages" && init?.method === "POST") {
        const body = JSON.parse(init.body as string);
        sentEnvelope = body.envelope;
        return jsonResponse(201, {
          id: "msg-dist-3",
          conversation_id: "grp-3",
          sender_id: "me",
          sender_identity_key_id: "me-key",
          ciphertext: body.ciphertext,
          envelope: body.envelope,
          sent_at: "2030-01-03T00:00:01Z",
        });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const ok = await useMessagingStore.getState().removeGroupMember("grp-3", "bob-id");

    expect(ok).toBe(true);
    expect(groupKeyStore.getCurrentEpoch("grp-3")).toBe(2);
    expect(sentEnvelope).not.toBeNull();
    const keyWraps = sentEnvelope!.keyWraps as Record<string, unknown>;
    // Only carol (the remaining member) gets the new epoch — bob is excluded.
    expect(Object.keys(keyWraps)).toEqual([carol.identityKeyId]);
  });

  it("onGroupMembershipChanged drops local state instead of fetching messages when we're no longer a member (fixes a console 403)", async () => {
    // Regression: a `conversation.participant_removed` WS event (e.g. this
    // device's own removal) used to unconditionally re-fetch the conversation's
    // messages when it was the active one — which 403s, since access was just
    // revoked. The fix checks post-refresh membership first.
    useMessagingStore.setState({
      identity: await meIdentity(),
      activeConversationId: "grp-4",
      conversations: [
        {
          id: "grp-4",
          type: "group",
          name: "Team",
          created_by: "someone-else",
          created_at: "2030-01-01T00:00:00Z",
          participants: [{ user_id: "me", role: "member", joined_at: "2030-01-01T00:00:00Z" }],
        },
      ],
      messagesByConversation: { "grp-4": [] },
    });

    let messagesFetched = false;
    fetchMock.mockImplementation(async (url: string) => {
      if (url === "/api/v1/conversations") {
        // Server no longer returns grp-4 — we were removed.
        return jsonResponse(200, []);
      }
      if (url.includes("/messages")) {
        messagesFetched = true;
        return jsonResponse(403, { error_code: "not_participant", message: "not a participant" });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    await useMessagingStore.getState().onGroupMembershipChanged("grp-4");

    expect(messagesFetched).toBe(false);
    const state = useMessagingStore.getState();
    expect(state.activeConversationId).toBeNull();
    expect(state.messagesByConversation["grp-4"]).toBeUndefined();
  });
});

describe("messagingStore — group no-key hiding + manual re-key (identity-rotation recovery)", () => {
  it("decryptConversationLog skips group messages whose epoch key is missing (no error bubble) and counts them", async () => {
    __resetDecryptCaches();
    groupKeyStore.clear("grp-nk");
    const me = await meIdentity();
    const conv: ConversationResponse = {
      id: "grp-nk",
      type: "group",
      name: "Team",
      created_by: "me",
      created_at: "2030-01-01T00:00:00Z",
      participants: [
        { user_id: "me", role: "group_admin", joined_at: "2030-01-01T00:00:00Z" },
        { user_id: "bob-id", role: "member", joined_at: "2030-01-01T00:00:00Z" },
      ],
    };
    // A content message sealed under epoch 1, sent AFTER me joined (so NOT a
    // pre-join skip) — but this device holds no epoch-1 key (an identity
    // rotation lost it). Must be skipped + counted, NOT rendered as an error.
    const msg: MessageResponse = {
      id: "m-nk",
      conversation_id: "grp-nk",
      sender_id: "bob-id",
      sender_identity_key_id: "bob-key",
      ciphertext: "AAAA",
      envelope: { alg: "aes-256-gcm", nonce: "AAAAAAAAAAAAAAAA", version: 1, epoch: 1 },
      sent_at: "2030-01-02T00:00:00Z",
    };
    const noKeyCount = await decryptConversationLog(conv, [msg], me);

    expect(noKeyCount).toBe(1);
    expect(getDecryptError("m-nk")).toBeNull();
    expect(getDecryptedText("m-nk")).toBeNull();
  });

  it("decryptConversationLog skips pre-join group messages entirely (not counted as no-key)", async () => {
    __resetDecryptCaches();
    groupKeyStore.clear("grp-pj");
    const me = await meIdentity();
    const conv: ConversationResponse = {
      id: "grp-pj",
      type: "group",
      name: "Team",
      created_by: "bob-id",
      created_at: "2030-01-01T00:00:00Z",
      participants: [
        // me joined at 00:02; a message sent at 00:01 is pre-join.
        { user_id: "me", role: "member", joined_at: "2030-01-01T00:02:00Z" },
        { user_id: "bob-id", role: "group_admin", joined_at: "2030-01-01T00:00:00Z" },
      ],
    };
    const preJoin: MessageResponse = {
      id: "m-pj",
      conversation_id: "grp-pj",
      sender_id: "bob-id",
      sender_identity_key_id: "bob-key",
      ciphertext: "AAAA",
      envelope: { alg: "aes-256-gcm", nonce: "AAAAAAAAAAAAAAAA", version: 1, epoch: 1 },
      sent_at: "2030-01-01T00:01:00Z",
    };
    const noKeyCount = await decryptConversationLog(conv, [preJoin], me);

    // Pre-join has its own "you were added" notice — not a no-key loss.
    expect(noKeyCount).toBe(0);
    expect(getDecryptError("m-pj")).toBeNull();
  });

  it("rekeyGroup bumps the epoch to one past the highest in the message history and distributes to every current member", async () => {
    // Recovery path: this device holds NO epoch key (the identity was rotated,
    // so the old epoch-1 wraps — addressed to the superseded keypair — can't be
    // unwrapped). The base epoch must come from the message history's plaintext
    // envelope.epoch metadata (1), not the empty local store (0), so the new
    // epoch is 2 — never colliding with / overwriting epoch 1.
    const me = await meIdentity();
    useMessagingStore.setState({ identity: me });
    const bob = await newFakeMember("bob-id", "bob");
    const oldMsg: MessageResponse = {
      id: "m-old",
      conversation_id: "grp-rk",
      sender_id: "bob-id",
      sender_identity_key_id: bob.identityKeyId,
      ciphertext: "AAAA",
      envelope: { alg: "aes-256-gcm", nonce: "AAAAAAAAAAAAAAAA", version: 1, epoch: 1 },
      sent_at: "2030-01-02T00:00:00Z",
    };
    useMessagingStore.setState({
      conversations: [
        {
          id: "grp-rk",
          type: "group",
          name: "Team",
          created_by: "me",
          created_at: "2030-01-01T00:00:00Z",
          participants: [
            { user_id: "me", role: "group_admin", joined_at: "2030-01-01T00:00:00Z" },
            { user_id: bob.userId, role: "member", joined_at: "2030-01-01T00:00:00Z" },
          ],
        },
      ],
      messagesByConversation: { "grp-rk": [oldMsg] },
    });
    expect(groupKeyStore.getCurrentEpoch("grp-rk")).toBeNull();

    let sentEnvelope: Record<string, unknown> | null = null;
    let distMsg: MessageResponse | null = null;
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === `/api/v1/users/${bob.userId}/identity-keys`) {
        return jsonResponse(200, identityKeysResponseFor(bob));
      }
      if (url === "/api/v1/conversations" && (!init || init.method === "GET")) {
        return jsonResponse(200, [
          {
            id: "grp-rk",
            type: "group",
            name: "Team",
            created_by: "me",
            created_at: "2030-01-01T00:00:00Z",
            participants: [
              { user_id: "me", role: "group_admin", joined_at: "2030-01-01T00:00:00Z" },
              { user_id: bob.userId, role: "member", joined_at: "2030-01-01T00:00:00Z" },
            ],
          },
        ]);
      }
      if (url === "/api/v1/conversations/grp-rk/messages" && init?.method === "POST") {
        const body = JSON.parse(init.body as string);
        sentEnvelope = body.envelope;
        distMsg = {
          id: "msg-dist-rk",
          conversation_id: "grp-rk",
          sender_id: "me",
          sender_identity_key_id: me.keyId,
          ciphertext: body.ciphertext,
          envelope: body.envelope,
          sent_at: "2030-01-03T00:00:01Z",
        };
        return jsonResponse(201, distMsg);
      }
      if (
        url.startsWith("/api/v1/conversations/grp-rk/messages") &&
        (!init || !init.method || init.method === "GET")
      ) {
        const list = distMsg ? [oldMsg, distMsg] : [oldMsg];
        return jsonResponse(200, { messages: list, next_cursor: null });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const ok = await useMessagingStore.getState().rekeyGroup("grp-rk");

    expect(ok).toBe(true);
    // New epoch is 2 (max message epoch 1 + 1), not 1 (would collide).
    expect(groupKeyStore.getCurrentEpoch("grp-rk")).toBe(2);
    expect(groupKeyStore.getKey("grp-rk", 2)).not.toBeNull();
    expect(sentEnvelope).not.toBeNull();
    expect(sentEnvelope!.epoch).toBe(2);
    // The wrap is addressed to the other current member's active identity key.
    const keyWraps = sentEnvelope!.keyWraps as Record<string, unknown>;
    expect(Object.keys(keyWraps)).toEqual([bob.identityKeyId]);
    // The old epoch-1 message is now hidden (no key) rather than rendered as
    // a "Couldn't decrypt … no group key for epoch 1" bubble.
    expect(useMessagingStore.getState().hiddenNoKeyCountByConversation["grp-rk"]).toBe(1);
    expect(getDecryptError("m-old")).toBeNull();
  });
});