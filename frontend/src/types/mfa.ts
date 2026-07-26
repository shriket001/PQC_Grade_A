/**
 * MFA/TOTP DTOs (FR-009) — mirror `backend/src/schemas/mfa.py`.
 */

export interface MfaEnrollResponse {
  /** `otpauth://` URI to render as a QR code for an authenticator app. */
  otpauth_uri: string;
  /** Same shared secret in base32, shown once for manual entry. */
  secret: string;
}

export interface MfaConfirmResponse {
  enabled: boolean;
}

/** Exactly one of `password`/`totp_code` must be set — proof the caller still
 * controls the account before turning MFA off. */
export type MfaDisableRequest =
  | { password: string; totp_code?: undefined }
  | { totp_code: string; password?: undefined };
