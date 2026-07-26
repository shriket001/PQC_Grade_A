import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setAccessToken } from "@/services/apiClient";
import { fetchProfile, getUserSummary, searchUsers } from "@/services/userService";

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  setAccessToken("a.b.c");
});

afterEach(() => {
  setAccessToken(null);
});

describe("userService — typed wrappers over the /users/* directory contract", () => {
  it("fetchProfile GETs /users/me and returns the profile DTO", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        id: "u-1",
        username: "alice",
        display_name: "Alice",
        email: "alice@example.com",
        email_verified: true,
        created_at: "2030-01-01T00:00:00Z",
      }),
    );

    const result = await fetchProfile();

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/users/me");
    expect(fetchMock.mock.calls[0][1].method).toBe("GET");
    expect(result.username).toBe("alice");
    expect(result.email).toBe("alice@example.com");
    expect(result.email_verified).toBe(true);
  });

  it("getUserSummary GETs /users/{id} (encoded) and returns the summary without email", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { id: "u-2", username: "bob", display_name: "bob" }),
    );

    const result = await getUserSummary("u-2 with space");

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/users/u-2%20with%20space");
    expect(result.username).toBe("bob");
    expect("email" in result).toBe(false);
  });

  it("searchUsers GETs /users/search?q= with the trimmed, encoded handle", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, [{ id: "u-2", username: "bob", display_name: "bob" }]),
    );

    const result = await searchUsers("  Bob  ");

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/users/search?q=Bob");
    expect(result).toHaveLength(1);
    expect(result[0].username).toBe("bob");
    expect("email" in result[0]).toBe(false);
  });

  it("searchUsers returns an empty list (no throw) when the handle is unknown", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, []));
    const result = await searchUsers("nobody");
    expect(result).toEqual([]);
  });

  it("searchUsers short-circuits below the 2-character minimum without a network call", async () => {
    const result = await searchUsers("b");
    expect(result).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});