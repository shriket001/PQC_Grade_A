/**
 * Auth service — thin typed wrappers over the live `/api/v1/auth/*` contract
 * (US1 / Phase 4). Each call returns the typed DTO or throws an `ApiError`
 * carrying the backend's `error_code`; pages map codes to user guidance via
 * `AUTH_ERROR_GUIDANCE`.
 */

import { apiClient, setAccessToken } from "@/services/apiClient";
import type {
  LoginRequest,
  RegisterRequest,
  RegisterResponse,
  TokenResponse,
  VerifyEmailRequest,
  VerifyEmailResponse,
} from "@/types/auth";

export async function refresh(): Promise<TokenResponse> {
  // No body: the refresh token is never held in JS (FR-005/US10) — the
  // browser attaches it automatically as the HttpOnly cookie `apiClient`
  // requests via `credentials: "include"`.
  const tokens = await apiClient.post<TokenResponse>("/auth/refresh");
  // Same rationale as `login`: hydrate the bearer header immediately so the
  // caller's next request (or a request already queued behind this refresh)
  // is authorized with the rotated token.
  setAccessToken(tokens.access_token);
  return tokens;
}

export async function register(input: RegisterRequest): Promise<RegisterResponse> {
  return apiClient.post<RegisterResponse>("/auth/register", input);
}

export async function verifyEmail(input: VerifyEmailRequest): Promise<VerifyEmailResponse> {
  return apiClient.post<VerifyEmailResponse>("/auth/verify-email", input);
}

export async function login(input: LoginRequest): Promise<TokenResponse> {
  const tokens = await apiClient.post<TokenResponse>("/auth/login", {
    ...input,
    device_context: input.device_context ?? "web",
  });
  // Hydrate the apiClient's bearer header immediately so the first
  // authenticated call (e.g. logout) is already authorized.
  setAccessToken(tokens.access_token);
  return tokens;
}

export async function logout(): Promise<void> {
  await apiClient.post<void>("/auth/logout");
  setAccessToken(null);
}
