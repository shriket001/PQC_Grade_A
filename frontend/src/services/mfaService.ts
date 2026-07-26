/**
 * MFA/TOTP service — thin typed wrappers over `/api/v1/auth/mfa/totp/*` (FR-009).
 */

import { apiClient } from "@/services/apiClient";
import type {
  MfaConfirmResponse,
  MfaDisableRequest,
  MfaEnrollResponse,
} from "@/types/mfa";

export async function enrollMfa(): Promise<MfaEnrollResponse> {
  return apiClient.post<MfaEnrollResponse>("/auth/mfa/totp/enroll");
}

export async function confirmMfa(totpCode: string): Promise<MfaConfirmResponse> {
  return apiClient.post<MfaConfirmResponse>("/auth/mfa/totp/confirm", {
    totp_code: totpCode,
  });
}

export async function disableMfa(proof: MfaDisableRequest): Promise<void> {
  await apiClient.delete<void>("/auth/mfa/totp", proof);
}
