import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient, setAccessToken, setUnauthorizedHandler } from "../src/services/apiClient";

describe("apiClient scaffold (Foundational phase)", () => {
  it("exposes the expected REST verb methods", () => {
    expect(typeof apiClient.get).toBe("function");
    expect(typeof apiClient.post).toBe("function");
    expect(typeof apiClient.patch).toBe("function");
    expect(typeof apiClient.delete).toBe("function");
  });

  it("setAccessToken does not throw for null or a token value", () => {
    expect(() => setAccessToken(null)).not.toThrow();
    expect(() => setAccessToken("test-token")).not.toThrow();
    setAccessToken(null);
  });
});

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

describe("apiClient 401 refresh-and-retry", () => {
  beforeEach(() => {
    setAccessToken("expired-token");
  });

  afterEach(() => {
    setAccessToken(null);
    setUnauthorizedHandler(null);
    vi.unstubAllGlobals();
  });

  it("retries the request once after the unauthorized handler refreshes successfully", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(401, { error_code: "unauthenticated" }))
      .mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    setUnauthorizedHandler(vi.fn().mockResolvedValue(true));

    const result = await apiClient.get<{ ok: boolean }>("/conversations");

    expect(result).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("surfaces the 401 when the unauthorized handler fails to refresh", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(401, { error_code: "unauthenticated" })));
    setUnauthorizedHandler(vi.fn().mockResolvedValue(false));

    await expect(apiClient.get("/conversations")).rejects.toMatchObject({
      status: 401,
      errorCode: "unauthenticated",
    });
  });

  it("never invokes the unauthorized handler for /auth/* routes (avoids a refresh loop)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(401, { error_code: "invalid_refresh_token" })),
    );
    const handler = vi.fn().mockResolvedValue(true);
    setUnauthorizedHandler(handler);

    await expect(apiClient.post("/auth/refresh")).rejects.toMatchObject({
      status: 401,
    });
    expect(handler).not.toHaveBeenCalled();
  });

  it("only calls the handler once for two requests that 401 concurrently", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(401, { error_code: "unauthenticated" }))
      .mockResolvedValueOnce(jsonResponse(401, { error_code: "unauthenticated" }))
      .mockResolvedValueOnce(jsonResponse(200, { ok: 1 }))
      .mockResolvedValueOnce(jsonResponse(200, { ok: 2 }));
    vi.stubGlobal("fetch", fetchMock);
    const handler = vi.fn().mockResolvedValue(true);
    setUnauthorizedHandler(handler);

    await Promise.all([apiClient.get("/a"), apiClient.get("/b")]);

    expect(handler).toHaveBeenCalledTimes(1);
  });
});
