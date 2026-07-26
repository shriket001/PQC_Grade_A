/**
 * REST + WebSocket API client scaffold.
 *
 * IMPORTANT: this module transports only ciphertext + envelope metadata for
 * message/file content (contracts/rest-api.md, contracts/websocket-events.md).
 * It must never be passed plaintext message/file content or private key
 * material (spec FR-051) — those stay inside `src/crypto/`.
 */

import type { AuthErrorCode } from "@/types/auth";

// Exported so callers that need a plain browser navigation rather than a
// fetch (e.g. the OAuth/OIDC "Sign in with Google" link, which must be a
// real top-level redirect to the external IdP) can build the URL themselves.
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

let accessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

/**
 * Registered by `authStore` (the only place with a session to refresh),
 * mirroring the `setAccessToken` handoff pattern so `apiClient` never imports
 * the store directly (that would be circular — the store imports this file).
 * Returns whether the refresh succeeded; the caller retries once on `true`.
 */
let onUnauthorized: (() => Promise<boolean>) | null = null;

export function setUnauthorizedHandler(handler: (() => Promise<boolean>) | null): void {
  onUnauthorized = handler;
}

// Concurrent requests that all 401 at once (e.g. several parallel fetches
// right as the access token expires) must share ONE refresh attempt — the
// backend's refresh token is single-use (rotated on redemption), so a second
// concurrent call with the same raw token would itself come back invalid.
let refreshInFlight: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  if (!onUnauthorized) return false;
  if (!refreshInFlight) {
    refreshInFlight = onUnauthorized().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

/**
 * Structured API error carrying the backend's `error_code` (FR-022) so callers
 * can branch on it without parsing strings. Falls back to `unknown_error` when
 * the body isn't the expected `{error_code, message}` shape.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly errorCode: AuthErrorCode;

  constructor(status: number, errorCode: AuthErrorCode, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.errorCode = errorCode;
  }
}

async function throwApiError(path: string, response: Response): Promise<never> {
  const body = await response.json().catch(() => null);
  const errorCode = (body?.error_code ?? "unknown_error") as AuthErrorCode;
  const message = body?.message ?? `Request to ${path} failed with ${response.status}`;
  throw new ApiError(response.status, errorCode, message);
}

// `/auth/*` 401s are the credential/refresh calls themselves (wrong password,
// dead refresh token, missing bearer on login) — never route those through
// the refresh-and-retry dance, or a dead refresh token would try to refresh
// itself forever.
function isAuthRoute(path: string): boolean {
  return path.startsWith("/auth/");
}

async function request<T>(path: string, init: RequestInit = {}, retried = false): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }

  // `credentials: "include"` — the HttpOnly refresh-token cookie (FR-005/US10)
  // only round-trips on /auth/login|refresh|logout if every request explicitly
  // opts in; the default "same-origin" mode is fragile here since it depends
  // on nothing ever proxying this API from a different origin.
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers,
    credentials: "include",
  });
  if (response.status === 401 && !retried && !isAuthRoute(path) && (await tryRefresh())) {
    return request<T>(path, init, true);
  }
  if (!response.ok) {
    await throwApiError(path, response);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

/** Binary/blob result of `apiClient.getBinary` — the raw bytes plus any
 * response headers the caller needs (e.g. file metadata carried in
 * `X-File-*` headers, since the body itself is opaque ciphertext). */
export interface BinaryResponse {
  blob: Blob;
  headers: Headers;
}

export const apiClient = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: body ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "DELETE", body: body ? JSON.stringify(body) : undefined }),
  /** Multipart upload — no Content-Type header, the browser sets the
   * multipart boundary itself when the body is a `FormData`. */
  postForm: async <T>(path: string, form: FormData, retried = false): Promise<T> => {
    const headers = new Headers();
    if (accessToken) {
      headers.set("Authorization", `Bearer ${accessToken}`);
    }
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      body: form,
      headers,
      credentials: "include",
    });
    if (response.status === 401 && !retried && !isAuthRoute(path) && (await tryRefresh())) {
      return apiClient.postForm<T>(path, form, true);
    }
    if (!response.ok) {
      await throwApiError(path, response);
    }
    return response.json() as Promise<T>;
  },
  /** Binary download — skips `response.json()`, returns the raw blob plus
   * headers (used for opaque file ciphertext + its crypto envelope, carried
   * in `X-File-*` response headers). */
  getBinary: async (path: string, retried = false): Promise<BinaryResponse> => {
    const headers = new Headers();
    if (accessToken) {
      headers.set("Authorization", `Bearer ${accessToken}`);
    }
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method: "GET",
      headers,
      credentials: "include",
    });
    if (response.status === 401 && !retried && !isAuthRoute(path) && (await tryRefresh())) {
      return apiClient.getBinary(path, true);
    }
    if (!response.ok) {
      await throwApiError(path, response);
    }
    return { blob: await response.blob(), headers: response.headers };
  },
};

export function openRealtimeConnection(): WebSocket {
  // Must derive the scheme from the PAGE's protocol, not string-replace
  // "http" out of API_BASE_URL — that regex only ever matches when
  // API_BASE_URL is itself an absolute URL. The default/dev value is the
  // relative path "/api/v1", which doesn't start with "http" at all, so the
  // old code silently built a `new URL(relativePath, origin)` that inherited
  // http/https from the page — and the WebSocket constructor throws a
  // SyntaxError for any scheme other than ws/wss (this was surfacing as a
  // silent failure to connect under plain http, and would fail outright once
  // the app is served over https).
  const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const isAbsolute = /^https?:\/\//.test(API_BASE_URL);
  const base = isAbsolute
    ? API_BASE_URL.replace(/^https?:/, wsProtocol)
    : `${wsProtocol}//${window.location.host}${API_BASE_URL}`;
  const url = new URL(`${base}/ws`);
  if (accessToken) {
    url.searchParams.set("access_token", accessToken);
  }
  return new WebSocket(url);
}
