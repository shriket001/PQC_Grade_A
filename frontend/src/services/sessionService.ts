/**
 * Session/device management service — thin typed wrappers over
 * `/api/v1/auth/sessions` (FR-006/US10).
 */

import { apiClient } from "@/services/apiClient";
import type { SessionResponse } from "@/types/auth";

export async function listSessions(): Promise<SessionResponse[]> {
  return apiClient.get<SessionResponse[]>("/auth/sessions");
}

export async function revokeSession(sessionId: string): Promise<void> {
  await apiClient.delete<void>(`/auth/sessions/${sessionId}`);
}
