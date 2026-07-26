/**
 * @jest-environment jsdom
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { DevicesModal } from "@/components/DevicesModal";
import { setAccessToken } from "@/services/apiClient";

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

describe("DevicesModal", () => {
  it("lists devices, labels the current one, and shows Sign out for others", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, [
        {
          session_id: "s1",
          device_context: "Chrome on Windows",
          created_at: "2030-01-01T00:00:00Z",
          current: true,
        },
        {
          session_id: "s2",
          device_context: "iPhone",
          created_at: "2030-01-02T00:00:00Z",
          current: false,
        },
      ]),
    );

    render(<DevicesModal />);

    await waitFor(() => expect(screen.getByText("Chrome on Windows")).toBeInTheDocument());
    expect(screen.getByText("This device")).toBeInTheDocument();
    expect(screen.getByText("iPhone")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });

  it("revoking a device removes it from the list", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse(200, [
          { session_id: "s1", device_context: "Chrome", created_at: "2030-01-01T00:00:00Z", current: true },
          { session_id: "s2", device_context: "iPhone", created_at: "2030-01-02T00:00:00Z", current: false },
        ]),
      )
      .mockResolvedValueOnce(jsonResponse(204, null));

    render(<DevicesModal />);
    await waitFor(() => expect(screen.getByText("iPhone")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));

    await waitFor(() => expect(screen.queryByText("iPhone")).not.toBeInTheDocument());
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/auth/sessions/s2");
    expect(fetchMock.mock.calls[1][1].method).toBe("DELETE");
  });

  it("shows guidance text when the initial list fails to load", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(500, { error_code: "unknown_error", message: "boom" }),
    );

    render(<DevicesModal />);

    await waitFor(() => {
      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    });
  });
});
