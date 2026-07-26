import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { bytesToBase64 } from "@/crypto/bytes";
import { conversationKeyStore } from "@/crypto/conversationCrypto";
import { packFilePlaintext, sealFile } from "@/crypto/fileCrypto";
import { mlDsa65IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { setAccessToken } from "@/services/apiClient";
import { useAuthStore } from "@/store/authStore";
import {
  __resetDecryptCaches,
  getDecryptedFile,
  getFileLoadError,
  isFileMessage,
  useMessagingStore,
} from "@/store/messagingStore";
import type { LocalIdentity } from "@/crypto/vault";
import type { ConversationResponse, MessageResponse } from "@/types/messaging";

const futureIso = new Date(Date.now() + 60_000).toISOString();
const CONV_ID = "conv-file-1";

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

function binaryResponse(status: number, blobBody: Blob, headers: Record<string, string>): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    headers: new Headers(headers),
    json: async () => null,
    blob: async () => blobBody,
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
    fileCacheVersion: 0,
  });
}

async function meIdentity(): Promise<LocalIdentity> {
  const signing = await mlDsa65IdentityKeyProvider.generateKeyPair();
  return {
    keyId: "me-key",
    deviceLabel: "dev",
    signingPublicKey: signing.publicKey,
    signingPrivateKey: signing.privateKey,
    kemPublicKey: new Uint8Array(32),
    kemPrivateKey: new Uint8Array(32),
    wrapKey: null,
    wrapKdfSalt: null,
    wrapKdfParams: null,
  };
}

function directConversation(): ConversationResponse {
  return {
    id: CONV_ID,
    type: "direct",
    name: null,
    created_by: "me",
    created_at: "2030-01-01T00:00:00Z",
    last_message_at: null,
    participants: [
      { user_id: "me", role: null, joined_at: "2030-01-01T00:00:00Z" },
      { user_id: "bob-id", role: null, joined_at: "2030-01-01T00:00:00Z" },
    ],
  };
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

describe("messagingStore.isFileMessage", () => {
  it("recognizes a file-kind envelope and not a plain text one", () => {
    const fileMsg = {
      envelope: { alg: "a", nonce: "n", version: 1, kind: "file" },
    } as unknown as MessageResponse;
    const textMsg = {
      envelope: { alg: "a", nonce: "n", version: 1 },
    } as unknown as MessageResponse;
    expect(isFileMessage(fileMsg)).toBe(true);
    expect(isFileMessage(textMsg)).toBe(false);
  });
});

describe("messagingStore.sendFile", () => {
  it("rejects a disallowed file type without calling the API", async () => {
    const me = await meIdentity();
    useMessagingStore.setState({
      identity: me,
      conversations: [directConversation()],
      activeConversationId: CONV_ID,
    });
    conversationKeyStore.set(CONV_ID, {
      messageKey: crypto.getRandomValues(new Uint8Array(32)),
      peerSigningPublicKey: new Uint8Array(0),
    });

    const badFile = new File([new Uint8Array([1, 2, 3])], "archive.zip");
    await useMessagingStore.getState().sendFile(badFile);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(useMessagingStore.getState().error).toMatch(/aren't supported/);
  });

  it("errors instead of sending when no conversation key is established yet", async () => {
    const me = await meIdentity();
    useMessagingStore.setState({
      identity: me,
      conversations: [directConversation()],
      activeConversationId: CONV_ID,
    });
    // No conversationKeyStore.set — nothing established, no server backup
    // mocked either (fetchConversationKeyBackup will 404 and resolve null).
    fetchMock.mockResolvedValue(jsonResponse(404, { error_code: "not_found", message: "x" }));

    const file = new File([new Uint8Array([1, 2, 3])], "photo.png");
    await useMessagingStore.getState().sendFile(file);

    expect(useMessagingStore.getState().error).toMatch(/text message first/);
  });

  it("encrypts and uploads a file, appending a file-kind message", async () => {
    const me = await meIdentity();
    useMessagingStore.setState({
      identity: me,
      conversations: [directConversation()],
      activeConversationId: CONV_ID,
    });
    const messageKey = crypto.getRandomValues(new Uint8Array(32));
    conversationKeyStore.set(CONV_ID, { messageKey, peerSigningPublicKey: new Uint8Array(0) });

    let uploadedForm: FormData | null = null;
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === `/api/v1/conversations/${CONV_ID}/files` && init?.method === "POST") {
        uploadedForm = init.body as FormData;
        return jsonResponse(201, {
          file_attachment_id: "file-1",
          message_id: "msg-1",
          content_type: "application/pdf",
          size_bytes: 3,
          upload_status: "complete",
          sent_at: "2030-01-01T00:00:01Z",
        });
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const file = new File([new Uint8Array([65, 66, 67])], "report.pdf", { type: "application/pdf" });
    await useMessagingStore.getState().sendFile(file);

    expect(useMessagingStore.getState().error).toBeNull();
    expect(uploadedForm).not.toBeNull();
    expect(uploadedForm!.get("sender_identity_key_id")).toBe("me-key");
    expect(uploadedForm!.get("content_type")).toBe("application/pdf");

    const state = useMessagingStore.getState();
    const messages = state.messagesByConversation[CONV_ID];
    expect(messages).toHaveLength(1);
    expect(messages[0].id).toBe("msg-1");
    expect(isFileMessage(messages[0])).toBe(true);
    expect(messages[0].envelope.file_attachment_id).toBe("file-1");

    // Sender already holds the plaintext — the file is cached immediately,
    // no download round trip needed for their own bubble.
    const cached = getDecryptedFile("msg-1");
    expect(cached?.filename).toBe("report.pdf");
    expect(cached?.contentType).toBe("application/pdf");
    expect(state.lastMessagePreviewByConversation[CONV_ID]).toContain("report.pdf");
  });
});

describe("messagingStore.loadFile", () => {
  it("downloads and decrypts a peer's shared file", async () => {
    const me = await meIdentity();
    const bobSigning = await mlDsa65IdentityKeyProvider.generateKeyPair();
    useMessagingStore.setState({
      identity: me,
      conversations: [directConversation()],
      activeConversationId: CONV_ID,
    });
    const messageKey = crypto.getRandomValues(new Uint8Array(32));
    conversationKeyStore.set(CONV_ID, { messageKey, peerSigningPublicKey: bobSigning.publicKey });

    const plaintext = packFilePlaintext("image.png", new Uint8Array([10, 20, 30]));
    const sealed = await sealFile(messageKey, plaintext, bobSigning.privateKey, CONV_ID, "bob-key");

    fetchMock.mockImplementation(async (url: string) => {
      if (url === `/api/v1/conversations/${CONV_ID}/files/file-9`) {
        return binaryResponse(200, new Blob([sealed.ciphertext.slice()]), {
          "X-File-Envelope": JSON.stringify(sealed.envelope),
          "X-File-Content-Type": "image/png",
        });
      }
      if (url === "/api/v1/users/bob-id/identity-keys") {
        return jsonResponse(200, [
          {
            id: "bob-key",
            user_id: "bob-id",
            device_label: "dev",
            public_signing_key: bytesToBase64(bobSigning.publicKey),
            public_kem_key: bytesToBase64(new Uint8Array(32)),
            key_version: 1,
            created_at: "2030-01-01T00:00:00Z",
            superseded_at: null,
          },
        ]);
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const message: MessageResponse = {
      id: "msg-9",
      conversation_id: CONV_ID,
      sender_id: "bob-id",
      sender_identity_key_id: "bob-key",
      ciphertext: "",
      envelope: { alg: "aes-256-gcm", nonce: "x", version: 1, kind: "file", file_attachment_id: "file-9" },
      sent_at: "2030-01-01T00:00:02Z",
    };

    await useMessagingStore.getState().loadFile(CONV_ID, message);

    expect(getFileLoadError("msg-9")).toBeNull();
    const file = getDecryptedFile("msg-9");
    expect(file?.filename).toBe("image.png");
    expect(file?.contentType).toBe("image/png");
    const bytes = new Uint8Array(await file!.blob.arrayBuffer());
    expect(Array.from(bytes)).toEqual([10, 20, 30]);
  });

  it("records a load error when the signature doesn't verify (wrong sender key)", async () => {
    const me = await meIdentity();
    const bobSigning = await mlDsa65IdentityKeyProvider.generateKeyPair();
    const wrongSigning = await mlDsa65IdentityKeyProvider.generateKeyPair();
    useMessagingStore.setState({
      identity: me,
      conversations: [directConversation()],
      activeConversationId: CONV_ID,
    });
    const messageKey = crypto.getRandomValues(new Uint8Array(32));
    conversationKeyStore.set(CONV_ID, { messageKey, peerSigningPublicKey: bobSigning.publicKey });

    const plaintext = packFilePlaintext("doc.pdf", new Uint8Array([1]));
    const sealed = await sealFile(messageKey, plaintext, bobSigning.privateKey, CONV_ID, "bob-key");

    fetchMock.mockImplementation(async (url: string) => {
      if (url === `/api/v1/conversations/${CONV_ID}/files/file-9`) {
        return binaryResponse(200, new Blob([sealed.ciphertext.slice()]), {
          "X-File-Envelope": JSON.stringify(sealed.envelope),
          "X-File-Content-Type": "application/pdf",
        });
      }
      if (url === "/api/v1/users/bob-id/identity-keys") {
        // Directory returns the WRONG public key for this sender — signature
        // verification must fail rather than silently trusting it.
        return jsonResponse(200, [
          {
            id: "bob-key",
            user_id: "bob-id",
            device_label: "dev",
            public_signing_key: bytesToBase64(wrongSigning.publicKey),
            public_kem_key: bytesToBase64(new Uint8Array(32)),
            key_version: 1,
            created_at: "2030-01-01T00:00:00Z",
            superseded_at: null,
          },
        ]);
      }
      return jsonResponse(404, { error_code: "unknown", message: "x" });
    });

    const message: MessageResponse = {
      id: "msg-10",
      conversation_id: CONV_ID,
      sender_id: "bob-id",
      sender_identity_key_id: "bob-key",
      ciphertext: "",
      envelope: { alg: "aes-256-gcm", nonce: "x", version: 1, kind: "file", file_attachment_id: "file-9" },
      sent_at: "2030-01-01T00:00:02Z",
    };

    await useMessagingStore.getState().loadFile(CONV_ID, message);

    expect(getDecryptedFile("msg-10")).toBeNull();
    expect(getFileLoadError("msg-10")).not.toBeNull();
  });
});
