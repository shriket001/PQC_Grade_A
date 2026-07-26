/**
 * @jest-environment jsdom
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { openRealtimeConnection, setAccessToken } from "@/services/apiClient";

class FakeWebSocket {
  static lastUrl: string | null = null;
  constructor(url: string | URL) {
    FakeWebSocket.lastUrl = url.toString();
  }
}

beforeEach(() => {
  FakeWebSocket.lastUrl = null;
  vi.stubGlobal("WebSocket", FakeWebSocket);
  setAccessToken(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("openRealtimeConnection", () => {
  it("builds a ws:// URL when the page is served over plain http", () => {
    expect(window.location.protocol).toBe("http:"); // jsdom's default test origin
    openRealtimeConnection();
    expect(FakeWebSocket.lastUrl).toMatch(/^ws:\/\/.*\/api\/v1\/ws$/);
  });

  it("builds a wss:// URL when the page is served over https", () => {
    Object.defineProperty(window, "location", {
      value: new URL("https://localhost:5173/"),
      writable: true,
    });
    openRealtimeConnection();
    expect(FakeWebSocket.lastUrl).toMatch(/^wss:\/\/.*\/api\/v1\/ws$/);
  });

  it("includes the access token as a query param when set", () => {
    setAccessToken("a.b.c");
    openRealtimeConnection();
    expect(FakeWebSocket.lastUrl).toContain("access_token=a.b.c");
  });
});
