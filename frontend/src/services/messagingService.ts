/**
 * Messaging service — typed wrappers over the US2 REST contract
 * (`/api/v1/users/*`, `/api/v1/conversations`, `/api/v1/conversations/{id}/messages`).
 *
 * Like `authService`, each call returns the typed DTO or throws an `ApiError`
 * carrying the backend's `error_code`. This module transports only ciphertext
 * + envelope metadata — never plaintext or private key material (FR-051).
 */

import { apiClient, ApiError } from "@/services/apiClient";
import type {
  AddParticipantRequest,
  ConversationKeyBackupResponse,
  ConversationParticipantResponse,
  ConversationResponse,
  CreateConversationRequest,
  IdentityKeyResponse,
  MessageListResponse,
  MessageResponse,
  PublicIdentityKeyResponse,
  PublishIdentityKeyRequest,
  PutConversationKeyBackupRequest,
  RotateIdentityKeyRequest,
  SendMessageRequest,
} from "@/types/messaging";

// ---- Identity key directory ------------------------------------------------

export async function publishIdentityKey(
  input: PublishIdentityKeyRequest,
): Promise<IdentityKeyResponse> {
  return apiClient.post<IdentityKeyResponse>("/users/me/identity-keys", input);
}

export async function rotateIdentityKey(input: RotateIdentityKeyRequest): Promise<IdentityKeyResponse> {
  return apiClient.post<IdentityKeyResponse>("/users/me/identity-keys/rotate", input);
}

/**
 * Auth-scoped fetch of the caller's active identity INCLUDING wrapped private
 * material (FR-054). Returns null when the caller has published no key yet
 * (the endpoint responds 404 in that case) so the bootstrap can decide to
 * generate + wrap + publish.
 */
export async function fetchMyWrappedIdentity(): Promise<IdentityKeyResponse | null> {
  try {
    return await apiClient.get<IdentityKeyResponse>("/users/me/identity-key");
  } catch (err) {
    // 404 = no active identity yet (first login / new account); any other
    // error (auth, network, …) propagates to the caller.
    if (err instanceof ApiError && err.status === 404) {
      return null;
    }
    throw err;
  }
}

export async function listIdentityKeys(userId: string): Promise<PublicIdentityKeyResponse[]> {
  return apiClient.get<PublicIdentityKeyResponse[]>(`/users/${userId}/identity-keys`);
}

// ---- Conversations ---------------------------------------------------------

export async function createConversation(
  input: CreateConversationRequest,
): Promise<ConversationResponse> {
  return apiClient.post<ConversationResponse>("/conversations", input);
}

export async function listConversations(): Promise<ConversationResponse[]> {
  return apiClient.get<ConversationResponse[]>("/conversations");
}

/**
 * Delete a conversation the caller is an active participant of. Direct
 * conversations are hard-deleted server-side (conversation + both memberships
 * + every message, via cascade); group conversations stay a per-user soft
 * delete (leave, FR-055) since a hard delete there would destroy the group for
 * every other member. Returns void on 204; throws an `ApiError` (404 if the
 * conversation doesn't exist, 403 if the caller isn't an active participant).
 */
export async function deleteConversation(conversationId: string): Promise<void> {
  await apiClient.delete<void>(`/conversations/${conversationId}`);
}

/** Add a member to a group conversation (FR-024, group_admin only). Throws
 * `ApiError` with `not_group_admin` (403), `conversation_type_mismatch` (400,
 * attempted on a direct conversation), or `participant_already_active` (409). */
export async function addParticipant(
  conversationId: string,
  input: AddParticipantRequest,
): Promise<ConversationParticipantResponse> {
  return apiClient.post<ConversationParticipantResponse>(
    `/conversations/${conversationId}/participants`,
    input,
  );
}

/** Remove a member from a group conversation, or leave it yourself
 * (FR-024/FR-028, group_admin-or-self). */
export async function removeParticipant(conversationId: string, userId: string): Promise<void> {
  await apiClient.delete<void>(`/conversations/${conversationId}/participants/${userId}`);
}

/**
 * Push the caller's wrapped per-conversation message key backup (extends
 * FR-054's identity-key recovery to the 1:1 conversation symmetric key — see
 * `conversationKeyBackup.ts`). Idempotent: a re-push overwrites the prior
 * backup for this (conversation, user) pair.
 */
export async function putConversationKeyBackup(
  conversationId: string,
  input: PutConversationKeyBackupRequest,
): Promise<ConversationKeyBackupResponse> {
  return apiClient.put<ConversationKeyBackupResponse>(
    `/conversations/${conversationId}/key-backup`,
    input,
  );
}

/**
 * Fetch the caller's wrapped per-conversation message key backup, or null if
 * none has been pushed yet (the server responds 404).
 */
export async function fetchConversationKeyBackup(
  conversationId: string,
): Promise<ConversationKeyBackupResponse | null> {
  try {
    return await apiClient.get<ConversationKeyBackupResponse>(
      `/conversations/${conversationId}/key-backup`,
    );
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      return null;
    }
    throw err;
  }
}

// ---- Messages --------------------------------------------------------------

export async function sendMessage(
  conversationId: string,
  input: SendMessageRequest,
): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>(
    `/conversations/${conversationId}/messages`,
    input,
  );
}

export async function listMessages(
  conversationId: string,
  beforeCursor?: string | null,
  limit?: number,
): Promise<MessageListResponse> {
  const params: string[] = [];
  if (beforeCursor) params.push(`before=${encodeURIComponent(beforeCursor)}`);
  if (limit) params.push(`limit=${limit}`);
  const query = params.length ? `?${params.join("&")}` : "";
  return apiClient.get<MessageListResponse>(`/conversations/${conversationId}/messages${query}`);
}