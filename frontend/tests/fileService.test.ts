import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, setAccessToken } from "@/services/apiClient";
import { downloadFile, uploadFile } from "@/services/fileService";

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

function binaryResponse(status: number, blobBody: Blob, headers: Record<string, string>): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    headers: new Headers(headers),
    json: async () => null,
    blob: async () => blobBody,
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

describe("fileService — uploadFile", () => {
  it("POSTs a multipart form to /conversations/{id}/files", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(201, {
        file_attachment_id: "file-1",
        message_id: "msg-1",
        content_type: "image/png",
        size_bytes: 3,
        upload_status: "complete",
        sent_at: "2030-01-01T00:00:00Z",
      }),
    );

    const result = await uploadFile("conv-1", {
      senderIdentityKeyId: "key-1",
      fileEnvelope: { alg: "aes-256-gcm", nonce: "bm9uY2U=", version: 1 },
      contentType: "image/png",
      ciphertext: new Uint8Array([1, 2, 3]),
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/conversations/conv-1/files");
    expect(init.method).toBe("POST");
    expect(init.body).toBeInstanceOf(FormData);
    const form = init.body as FormData;
    expect(form.get("sender_identity_key_id")).toBe("key-1");
    expect(form.get("content_type")).toBe("image/png");
    expect(form.get("size_bytes")).toBe("3");
    expect(JSON.parse(form.get("file_envelope") as string)).toEqual({
      alg: "aes-256-gcm",
      nonce: "bm9uY2U=",
      version: 1,
    });
    expect(form.get("file_ciphertext")).toBeInstanceOf(Blob);
    // No Content-Type header set manually — the browser assigns the
    // multipart boundary itself when the body is a FormData.
    expect((init.headers as Headers).get?.("Content-Type") ?? null).toBeNull();

    expect(result.file_attachment_id).toBe("file-1");
    expect(result.upload_status).toBe("complete");
  });

  it("throws ApiError with the backend error_code on failure", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(413, { error_code: "file_too_large", message: "too big" }),
    );

    await expect(
      uploadFile("conv-1", {
        senderIdentityKeyId: "key-1",
        fileEnvelope: { alg: "aes-256-gcm", nonce: "bm9uY2U=", version: 1 },
        contentType: "application/pdf",
        ciphertext: new Uint8Array([1]),
      }),
    ).rejects.toMatchObject({ status: 413, errorCode: "file_too_large" });
  });
});

describe("fileService — downloadFile", () => {
  it("GETs the file and parses envelope/content-type from headers", async () => {
    const bytes = new Uint8Array([9, 8, 7]);
    fetchMock.mockResolvedValue(
      binaryResponse(200, new Blob([bytes]), {
        "X-File-Envelope": JSON.stringify({ alg: "aes-256-gcm", nonce: "bm9uY2U=", version: 1 }),
        "X-File-Content-Type": "application/pdf",
      }),
    );

    const result = await downloadFile("conv-1", "file-1");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/conversations/conv-1/files/file-1");
    expect(init.method).toBe("GET");
    expect(result.contentType).toBe("application/pdf");
    expect(result.envelope).toEqual({ alg: "aes-256-gcm", nonce: "bm9uY2U=", version: 1 });
    expect(Array.from(result.ciphertext)).toEqual([9, 8, 7]);
  });

  it("throws when the envelope header is missing", async () => {
    fetchMock.mockResolvedValue(binaryResponse(200, new Blob([new Uint8Array([1])]), {}));
    await expect(downloadFile("conv-1", "file-1")).rejects.toThrow();
  });

  it("propagates ApiError on a 403", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(403, { error_code: "not_participant", message: "nope" }),
    );
    await expect(downloadFile("conv-1", "file-1")).rejects.toBeInstanceOf(ApiError);
  });
});
