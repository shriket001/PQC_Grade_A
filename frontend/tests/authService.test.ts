import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { apiClient, ApiError, setAccessToken } from "@/services/apiClient";
import { login, logout, refresh, register, verifyEmail } from "@/services/authService";

/** Build a fetch Response-like object for the mocked global. */
function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 204 ? "No Content" : "OK",
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  setAccessToken(null);
});

afterEach(() => {
  setAccessToken(null);
});

describe("authService", () => {
  it("register posts the typed body to /auth/register and returns the DTO", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(201, { user_id: "abc-123", username: "alice", status: "unverified" }),
    );

    const result = await register({
      email: "Alice@Example.com",
      password: "Sup3rSecret!",
      username: "Alice",
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/auth/register");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      email: "Alice@Example.com",
      password: "Sup3rSecret!",
      username: "Alice",
    });
    expect(result).toEqual({ user_id: "abc-123", username: "alice", status: "unverified" });
  });

  it("login sets the access token on the apiClient so the next call is authorized", async () => {
    // The refresh token is never in this body (FR-005/US10) — it travels
    // solely as an HttpOnly Set-Cookie header the browser handles itself,
    // invisible to this mocked-fetch layer.
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        access_token: "a.b.c",
        token_type: "Bearer",
        expires_at: "2030-01-01T00:00:00Z",
      }),
    );

    const tokens = await login({ email: "bob@example.com", password: "pw" });

    expect(tokens.access_token).toBe("a.b.c");
    expect(tokens).not.toHaveProperty("refresh_token");
    // The login call defaults device_context to "web".
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body).toMatchObject({ email: "bob@example.com", password: "pw", device_context: "web" });

    // A follow-up GET should now carry the bearer header.
    fetchMock.mockResolvedValue(jsonResponse(204, null));
    await apiClient.post("/auth/logout");
    const headers = new Headers(fetchMock.mock.calls[1][1].headers);
    expect(headers.get("Authorization")).toBe("Bearer a.b.c");
  });

  it("refresh posts no body and relies on the HttpOnly cookie", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        access_token: "new.access.token",
        token_type: "Bearer",
        expires_at: "2030-01-01T00:00:00Z",
      }),
    );

    const tokens = await refresh();

    expect(tokens.access_token).toBe("new.access.token");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/auth/refresh");
    expect(init.body).toBeUndefined();
    expect(init.credentials).toBe("include");
  });

  it("verifyEmail posts the token and returns { verified: true }", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { verified: true }));
    const result = await verifyEmail({ verification_token: "tok" });
    expect(result).toEqual({ verified: true });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/auth/verify-email");
  });

  it("maps a non-ok response into an ApiError carrying the backend error_code", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(409, { error_code: "email_already_registered", message: "exists" }),
    );

    await expect(register({ email: "x@y.z", password: "p", username: "x" })).rejects.toMatchObject({
      name: "ApiError",
      status: 409,
      errorCode: "email_already_registered",
    });
  });

  it("falls back to unknown_error when the error body is malformed", async () => {
    fetchMock.mockResolvedValue(jsonResponse(500, null));
    await expect(verifyEmail({ verification_token: "t" })).rejects.toMatchObject({
      errorCode: "unknown_error",
      status: 500,
    });
    expect(ApiError).toBeDefined();
  });

  it("logout clears the access token on the apiClient", async () => {
    setAccessToken("a.b.c");
    fetchMock.mockResolvedValue(jsonResponse(204, null));
    await logout();

    fetchMock.mockResolvedValue(jsonResponse(204, null));
    await apiClient.post("/auth/something");
    const headers = new Headers(fetchMock.mock.calls[1][1].headers);
    expect(headers.get("Authorization")).toBeNull();
  });
});