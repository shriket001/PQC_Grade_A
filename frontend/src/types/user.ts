/**
 * User-directory DTOs (US2 / Phase 5 — FR-052/FR-053) — mirror
 * `backend/src/schemas/user.py`.
 *
 * The summary projection is the public view of a user (username + display name
 * only); it NEVER carries `email`. Email + verification status appear only in
 * the self profile returned by `/users/me` (FR-022 / PII boundary).
 */

export interface UserSummaryResponse {
  id: string;
  username: string;
  display_name: string;
}

export interface UserProfileResponse {
  id: string;
  username: string;
  display_name: string;
  email: string;
  email_verified: boolean;
  created_at: string; // ISO 8601
  /** Whether this account currently has an active TOTP factor (FR-009). */
  mfa_enabled: boolean;
}