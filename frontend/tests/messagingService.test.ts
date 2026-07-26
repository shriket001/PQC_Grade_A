import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setAccessToken } from "@/services/apiClient";
import {
  addParticipant,
  createConversation,
  listConversations,
  listIdentityKeys,
  listMessages,
  publishIdentityKey,
  removeParticipant,
  rotateIdentityKey,
  sendMessage,
} from "@/services/messagingService";

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  setAccessToken("a.b.c");
});

afterEach(() => {
  setAccessToken(null);
});

describe("messagingService — typed REST wrappers over the US2 contract", () => {
  it("publishIdentityKey POSTs the typed body to /users/me/identity-keys", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(201, {
        id: "key-1",
        user_id: "me",
        key_version: 1,
        public_signing_key: "sig",
        public_kem_key: "kem",
        device_label: "web",
        created_at: "2030-01-01T00:00:00Z",
        superseded_at: null,
      }),
    );

    const result = await publishIdentityKey({
      public_signing_key: "sig",
      public_kem_key: "kem",
      device_label: "web",
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/users/me/identity-keys");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      public_signing_key: "sig",
      public_kem_key: "kem",
      device_label: "web",
    });
    expect(result.id).toBe("key-1");
  });

  it("rotateIdentityKey posts to the rotate endpoint with the new halves + attestation", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(201, {
        id: "key-2",
        user_id: "me",
        key_version: 2,
        public_signing_key: "sig2",
        public_kem_key: "kem2",
        device_label: "web",
        created_at: "2030-01-01T00:00:00Z",
        superseded_at: null,
      }),
    );

    await rotateIdentityKey({
      new_public_signing_key: "sig2",
      new_public_kem_key: "kem2",
      rotation_attestation: "att",
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/users/me/identity-keys/rotate");
    expect(JSON.parse(init.body as string)).toEqual({
      new_public_signing_key: "sig2",
      new_public_kem_key: "kem2",
      rotation_attestation: "att",
    });
  });

  it("listIdentityKeys GETs /users/{id}/identity-keys", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, []));
    await listIdentityKeys("user-7");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/users/user-7/identity-keys");
    expect(fetchMock.mock.calls[0][1].method).toBe("GET");
  });

  it("createConversation posts the participant list to /conversations", async () => {
    fetchMock.mockResolvedValue(jsonResponse(201, { id: "conv-1", participants: [] }));
    await createConversation({ type: "direct", participant_user_ids: ["user-7"], name: null });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/conversations");
    expect(JSON.parse(init.body as string)).toEqual({ type: "direct", participant_user_ids: ["user-7"], name: null });
  });

  it("listConversations GETs /conversations", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, []));
    await listConversations();
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/conversations");
  });

  it("sendMessage posts the ciphertext + envelope to the conversation messages endpoint", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(201, {
        id: "msg-1",
        conversation_id: "conv-1",
        sender_id: "me",
        sender_identity_key_id: "key-1",
        ciphertext: "ct",
        envelope: { alg: "aes-256-gcm", nonce: "n", version: 1, sig: "s" },
        sent_at: "2030-01-01T00:00:00Z",
      }),
    );

    const result = await sendMessage("conv-1", {
      ciphertext: "ct",
      envelope: { alg: "aes-256-gcm", nonce: "n", version: 1, sig: "s" },
      sender_identity_key_id: "key-1",
    });

    expect(result.id).toBe("msg-1");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/conversations/conv-1/messages");
    expect(JSON.parse(init.body as string)).toMatchObject({ ciphertext: "ct", sender_identity_key_id: "key-1" });
  });

  it("listMessages GETs the endpoint, appending a before cursor when provided", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { messages: [], next_cursor: null }),
    );
    await listMessages("conv-1", "2030-01-01T00:00:00Z|msg-9");
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v1/conversations/conv-1/messages?before=2030-01-01T00%3A00%3A00Z%7Cmsg-9",
    );
  });

  it("listMessages omits the query string when no cursor is given", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { messages: [], next_cursor: null }),
    );
    await listMessages("conv-1");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/conversations/conv-1/messages");
  });

  it("createConversation posts a group shape with a name and multiple ids", async () => {
    fetchMock.mockResolvedValue(jsonResponse(201, { id: "conv-grp", participants: [] }));
    await createConversation({
      type: "group",
      participant_user_ids: ["user-7", "user-8"],
      name: "Trip Planning",
    });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/conversations");
    expect(JSON.parse(init.body as string)).toEqual({
      type: "group",
      participant_user_ids: ["user-7", "user-8"],
      name: "Trip Planning",
    });
  });

  it("addParticipant posts the user id to the participants endpoint", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(201, { user_id: "user-9", role: "member", joined_at: "2030-01-01T00:00:00Z" }),
    );
    const result = await addParticipant("conv-grp", { user_id: "user-9" });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/conversations/conv-grp/participants");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ user_id: "user-9" });
    expect(result.role).toBe("member");
  });

  it("removeParticipant DELETEs /conversations/{id}/participants/{userId}", async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 204, headers: new Headers() } as Response);
    await removeParticipant("conv-grp", "user-9");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/conversations/conv-grp/participants/user-9");
    expect(init.method).toBe("DELETE");
  });
});