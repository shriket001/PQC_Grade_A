import { describe, expect, it } from "vitest";

import { unwrapConversationKey, wrapConversationKey } from "@/crypto/conversationKeyBackup";

const WRAP_KDF_PARAMS = "argon2id:t=3:m=65536:p=4";

describe("conversationKeyBackup — wrap/unwrap round-trip", () => {
  it("round-trips a message key under the same wrapKey + conversation id", async () => {
    const wrapKey = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const messageKey = crypto.getRandomValues(new Uint8Array(32));
    const conversationId = "11111111-1111-1111-1111-111111111111";

    const backup = await wrapConversationKey(
      wrapKey,
      salt,
      WRAP_KDF_PARAMS,
      messageKey,
      conversationId,
    );
    const unwrapped = await unwrapConversationKey(
      wrapKey,
      {
        conversation_id: conversationId,
        wrapped_key: backup.wrapped_key,
        wrap_nonce: backup.wrap_nonce,
        wrap_kdf_salt: backup.wrap_kdf_salt,
        wrap_kdf_params: backup.wrap_kdf_params,
        wrap_alg: backup.wrap_alg,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
      conversationId,
    );

    expect(unwrapped).toEqual(messageKey);
  });

  it("fails to unwrap with the wrong wrapKey (tag mismatch)", async () => {
    const wrapKey = crypto.getRandomValues(new Uint8Array(32));
    const wrongKey = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const messageKey = crypto.getRandomValues(new Uint8Array(32));
    const conversationId = "22222222-2222-2222-2222-222222222222";

    const backup = await wrapConversationKey(
      wrapKey,
      salt,
      WRAP_KDF_PARAMS,
      messageKey,
      conversationId,
    );
    await expect(
      unwrapConversationKey(
        wrongKey,
        {
          conversation_id: conversationId,
          wrapped_key: backup.wrapped_key,
          wrap_nonce: backup.wrap_nonce,
          wrap_kdf_salt: backup.wrap_kdf_salt,
          wrap_kdf_params: backup.wrap_kdf_params,
          wrap_alg: backup.wrap_alg,
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
        conversationId,
      ),
    ).rejects.toThrow();
  });

  it("fails to unwrap against a different conversation id — AAD binding", async () => {
    const wrapKey = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const messageKey = crypto.getRandomValues(new Uint8Array(32));
    const conversationId = "33333333-3333-3333-3333-333333333333";
    const otherConversationId = "44444444-4444-4444-4444-444444444444";

    const backup = await wrapConversationKey(
      wrapKey,
      salt,
      WRAP_KDF_PARAMS,
      messageKey,
      conversationId,
    );
    // Replaying this backup blob as though it belonged to a different
    // conversation must fail — the AAD binds the ciphertext to its own id.
    await expect(
      unwrapConversationKey(
        wrapKey,
        {
          conversation_id: otherConversationId,
          wrapped_key: backup.wrapped_key,
          wrap_nonce: backup.wrap_nonce,
          wrap_kdf_salt: backup.wrap_kdf_salt,
          wrap_kdf_params: backup.wrap_kdf_params,
          wrap_alg: backup.wrap_alg,
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
        otherConversationId,
      ),
    ).rejects.toThrow();
  });
});
