/**
 * @jest-environment jsdom
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import { AuthBootstrap } from "@/components/AuthBootstrap";
import { useAuthStore } from "@/store/authStore";

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

beforeEach(() => {
  useAuthStore.setState({ session: null, bootstrapped: false });
});

describe("AuthBootstrap", () => {
  it("shows a loading state, then renders children once restoreSession resolves (no valid cookie)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(401, { error_code: "unauthenticated" })),
    );

    render(
      <AuthBootstrap>
        <div>app content</div>
      </AuthBootstrap>,
    );

    expect(screen.getByRole("status", { name: "Loading" })).toBeInTheDocument();
    expect(screen.queryByText("app content")).not.toBeInTheDocument();

    await waitFor(() => expect(screen.getByText("app content")).toBeInTheDocument());
    expect(useAuthStore.getState().session).toBeNull();

    vi.unstubAllGlobals();
  });

  it("renders children immediately once already bootstrapped (no flash on later navigations)", () => {
    useAuthStore.setState({ bootstrapped: true });

    render(
      <AuthBootstrap>
        <div>app content</div>
      </AuthBootstrap>,
    );

    expect(screen.getByText("app content")).toBeInTheDocument();
    expect(screen.queryByRole("status", { name: "Loading" })).not.toBeInTheDocument();
  });
});
