/**
 * User-directory service — typed wrappers over the `/api/v1/users/*` contract
 * (US2 / Phase 5 — FR-052/FR-053).
 *
 * This is how the UI resolves a typed username to a user id before starting a
 * direct conversation, and how it loads the signed-in user's own profile after
 * login (the JWT carries only `sub`/`sid` — the username reaches the UI through
 * `/users/me`, the correct non-workaround flow). Each call returns the typed DTO
 * or throws an `ApiError` carrying the backend's `error_code`.
 */

import { apiClient } from "@/services/apiClient";
import type { UserProfileResponse, UserSummaryResponse } from "@/types/user";

/** GET /users/me — the signed-in user's full profile (incl. email). */
export async function fetchProfile(): Promise<UserProfileResponse> {
  return apiClient.get<UserProfileResponse>("/users/me");
}

/** GET /users/{user_id} — a public summary by id (no email). */
export async function getUserSummary(userId: string): Promise<UserSummaryResponse> {
  return apiClient.get<UserSummaryResponse>(`/users/${encodeURIComponent(userId)}`);
}

/**
 * GET /users/search?q= — case-insensitive username PREFIX search, powering
 * both the "verify this peer exists" step and an autocomplete user picker.
 * Rate-limited and capped to a small result count server-side (never a bulk
 * account listing); never returns email. Returns `[]` for a query shorter
 * than 2 characters without hitting the network (matches the server's
 * `min_length=2`).
 */
export async function searchUsers(usernamePrefix: string): Promise<UserSummaryResponse[]> {
  const trimmed = usernamePrefix.trim();
  if (trimmed.length < 2) return [];
  return apiClient.get<UserSummaryResponse[]>(`/users/search?q=${encodeURIComponent(trimmed)}`);
}