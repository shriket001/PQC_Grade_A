import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setAccessToken } from "@/services/apiClient";
import { listSessions, revokeSession } from "@/services/sessionService";

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
  setAccessToken("a.b.c");
});

afterEach(() => {
  setAccessToken(null);
});

describe("sessionService", () => {
  it("listSessions GETs /auth/sessions and returns the DTO array", async () => {
    const sessions = [
      { session_id: "s1", device_context: "Chrome", created_at: "2030-01-01T00:00:00Z", current: true },
      { session_id: "s2", device_context: null, created_at: "2030-01-02T00:00:00Z", current: false },
    ];
    fetchMock.mockResolvedValue(jsonResponse(200, sessions));

    const result = await listSessions();

    expect(result).toEqual(sessions);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/auth/sessions");
    expect(init.method).toBe("GET");
  });

  it("revokeSession DELETEs /auth/sessions/{id}", async () => {
    fetchMock.mockResolvedValue(jsonResponse(204, null));

    await revokeSession("s1");

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/auth/sessions/s1");
    expect(init.method).toBe("DELETE");
  });
});
