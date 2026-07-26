import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setAccessToken } from "@/services/apiClient";
import { confirmMfa, disableMfa, enrollMfa } from "@/services/mfaService";

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

describe("mfaService", () => {
  it("enrollMfa posts to /auth/mfa/totp/enroll with no body and returns the DTO", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { otpauth_uri: "otpauth://totp/VAYUNX:x?secret=ABC", secret: "ABC" }),
    );

    const result = await enrollMfa();

    expect(result).toEqual({ otpauth_uri: "otpauth://totp/VAYUNX:x?secret=ABC", secret: "ABC" });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/auth/mfa/totp/enroll");
    expect(init.method).toBe("POST");
    expect(init.body).toBeUndefined();
  });

  it("confirmMfa posts the code and returns { enabled: true }", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { enabled: true }));

    const result = await confirmMfa("123456");

    expect(result).toEqual({ enabled: true });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/auth/mfa/totp/confirm");
    expect(JSON.parse(init.body as string)).toEqual({ totp_code: "123456" });
  });

  it("disableMfa sends a DELETE with the password proof", async () => {
    fetchMock.mockResolvedValue(jsonResponse(204, null));

    await disableMfa({ password: "Sup3rSecret!" });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/auth/mfa/totp");
    expect(init.method).toBe("DELETE");
    expect(JSON.parse(init.body as string)).toEqual({ password: "Sup3rSecret!" });
  });

  it("disableMfa sends a DELETE with the totp_code proof", async () => {
    fetchMock.mockResolvedValue(jsonResponse(204, null));

    await disableMfa({ totp_code: "654321" });

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({ totp_code: "654321" });
  });
});
