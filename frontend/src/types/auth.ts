/**
 * Auth DTOs and error vocabulary for the `/api/v1/auth/*` contract (US1).
 *
 * These mirror `backend/src/schemas/auth.py` exactly. The `error_code` set is
 * the stable surface the frontend codes against — see the Phase 4 report's
 * "Future Recommendations". The backend never sends an undocumented code; if it
 * ever does, `AuthServiceError` falls back to `unknown_error` + the server
 * message so the UI never shows a blank error.
 */

export interface RegisterRequest {
  email: string;
  password: string;
  /**
   * Public handle — the unique identifier users type to find each other.
   * Backend normalizes to lowercase and enforces `^[a-zA-Z0-9_]{3,32}$`.
   */
  username: string;
}

export interface VerifyEmailRequest {
  verification_token: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  device_context?: string;
  /** Required only if the account has TOTP MFA enabled (FR-009). */
  totp_code?: string;
}

/**
 * POST /auth/login or /auth/refresh — the access-token bundle. The refresh
 * token is NEVER in this body: it travels solely as an HttpOnly cookie the
 * browser attaches automatically, so it's unreadable to any XSS payload
 * (FR-005/US10). `apiClient` sends `credentials: "include"` so that cookie
 * round-trips on every request.
 */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_at: string; // ISO 8601
}

export interface RegisterResponse {
  user_id: string;
  username: string; // normalized handle echoed back by the backend
  status: string; // "unverified" until email verification completes
}

export interface VerifyEmailResponse {
  verified: boolean;
}

/** GET /auth/sessions — one entry per active login/device (FR-006/US10). */
export interface SessionResponse {
  session_id: string;
  device_context: string | null;
  created_at: string; // ISO 8601
  /** True for the session the CURRENT request is authenticated under. */
  current: boolean;
}

/** The closed set of auth-domain error codes emitted by the backend. */
export type AuthErrorCode =
  | "weak_password"
  | "email_already_registered"
  | "username_taken"
  | "invalid_verification_token"
  | "invalid_credentials"
  | "email_not_verified"
  | "account_disabled"
  | "unauthenticated"
  | "invalid_refresh_token"
  | "mfa_required"
  | "invalid_mfa_code"
  | "mfa_already_enabled"
  | "mfa_enrollment_not_found"
  | "mfa_not_enabled"
  | "session_not_found"
  | "oauth_failed"
  | "oauth_unavailable"
  | "saml_failed"
  | "saml_unavailable"
  | "rate_limited"
  | "unknown_error"; // fallback if the backend sends something unexpected

/** Human-readable guidance for each code, written from the user's side. */
export const AUTH_ERROR_GUIDANCE: Record<AuthErrorCode, string> = {
  weak_password:
    "Choose a stronger password: at least 12 characters with a lowercase letter, an uppercase letter, and a digit.",
  email_already_registered: "An account already exists for this email. Try signing in instead.",
  username_taken: "That username is taken. Try another handle.",
  invalid_verification_token:
    "This verification link is invalid or has already been used. Request a new one.",
  invalid_credentials: "Wrong email or password. Please try again.",
  email_not_verified:
    "Check your inbox for the verification email and confirm your address before signing in.",
  account_disabled: "This account has been disabled. Contact your administrator to restore access.",
  unauthenticated: "Your session has ended. Please sign in again.",
  invalid_refresh_token: "Your session has ended. Please sign in again.",
  mfa_required: "Enter the 6-digit code from your authenticator app.",
  invalid_mfa_code: "That code didn't match. Check your authenticator app and try again.",
  mfa_already_enabled: "Two-factor authentication is already enabled on this account.",
  mfa_enrollment_not_found: "Start enrollment again before confirming a code.",
  mfa_not_enabled: "Two-factor authentication isn't enabled on this account.",
  session_not_found: "That session is no longer active.",
  oauth_failed: "Sign-in with Google didn't complete. Please try again.",
  oauth_unavailable: "Sign-in with Google isn't available right now.",
  saml_failed: "Single sign-on didn't complete. Please try again.",
  saml_unavailable: "Single sign-on isn't available right now.",
  rate_limited: "Too many attempts in a row. Wait a minute and try again.",
  unknown_error: "Something went wrong on our side. Please try again shortly.",
};
