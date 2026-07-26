/**
 * @jest-environment jsdom
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Login from "@/pages/Login";
import { setAccessToken } from "@/services/apiClient";
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

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  setAccessToken(null);
  useAuthStore.getState().signOut();
});

afterEach(() => {
  vi.restoreAllMocks();
});

function renderLogin(initialEntry = "/login") {
  return render(
    <MemoryRouter
      initialEntries={[initialEntry]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <Login />
    </MemoryRouter>,
  );
}

function fillCredentials(email: string, password: string): void {
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: password } });
}

describe("Login page", () => {
  it("submits email + password with no totp_code on a normal login", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        access_token: "a.b.c",
        token_type: "Bearer",
        expires_at: "2030-01-01T00:00:00Z",
      }),
    );
    renderLogin();

    fillCredentials("alice@example.com", "Sup3rSecret!");
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.totp_code).toBeUndefined();
    expect(useAuthStore.getState().session?.accessToken).toBe("a.b.c");
  });

  it("shows the authenticator-code field after mfa_required, and resubmits with the code", async () => {
    renderLogin();
    fillCredentials("bob@example.com", "Sup3rSecret!");

    // First submit: password correct, no code yet -> backend asks for one.
    fetchMock.mockResolvedValueOnce(
      jsonResponse(401, { error_code: "mfa_required", message: "code required" }),
    );
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByLabelText("Authenticator code")).toBeInTheDocument();
    });
    expect(screen.getByText(/enter the 6-digit code/i)).toBeInTheDocument();

    // Second submit: include the code this time.
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        access_token: "a.b.c",
        token_type: "Bearer",
        expires_at: "2030-01-01T00:00:00Z",
      }),
    );
    fireEvent.change(screen.getByLabelText("Authenticator code"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => expect(useAuthStore.getState().session?.accessToken).toBe("a.b.c"));
    const secondBody = JSON.parse(fetchMock.mock.calls[1][1].body as string);
    expect(secondBody.totp_code).toBe("123456");
  });

  it("keeps the code field visible and shows guidance after a wrong code", async () => {
    renderLogin();
    fillCredentials("carol@example.com", "Sup3rSecret!");

    fetchMock.mockResolvedValueOnce(
      jsonResponse(401, { error_code: "mfa_required", message: "code required" }),
    );
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await waitFor(() => screen.getByLabelText("Authenticator code"));

    fetchMock.mockResolvedValueOnce(
      jsonResponse(401, { error_code: "invalid_mfa_code", message: "bad code" }),
    );
    fireEvent.change(screen.getByLabelText("Authenticator code"), {
      target: { value: "000000" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText(/didn't match/i)).toBeInTheDocument();
    });
    // Still showing the code field for another attempt, not bounced back to a
    // plain email/password form.
    expect(screen.getByLabelText("Authenticator code")).toBeInTheDocument();
  });

  it("renders a Google sign-in link pointing at the OIDC authorize endpoint", () => {
    renderLogin();
    const link = screen.getByRole("link", { name: /sign in with google/i });
    expect(link).toHaveAttribute("href", "/api/v1/auth/oidc/google/authorize");
  });

  it("shows guidance when bounced back from a failed Google sign-in", () => {
    renderLogin("/login?error=oauth_failed");
    expect(screen.getByText(/didn't complete/i)).toBeInTheDocument();
  });

  it("shows guidance when Google sign-in is not configured", () => {
    renderLogin("/login?error=oauth_unavailable");
    expect(screen.getByText(/isn't available right now/i)).toBeInTheDocument();
  });

  it("ignores an unrecognized error query param rather than crashing", () => {
    renderLogin("/login?error=something_unexpected");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("renders an SSO sign-in link pointing at the SAML login endpoint", () => {
    renderLogin();
    const link = screen.getByRole("link", { name: /sign in with sso/i });
    expect(link).toHaveAttribute("href", "/api/v1/auth/saml/samltest/login");
  });

  it("shows guidance when bounced back from a failed SAML sign-in", () => {
    renderLogin("/login?error=saml_failed");
    expect(screen.getByText(/single sign-on didn't complete/i)).toBeInTheDocument();
  });

  it("shows guidance when SAML sign-in is not configured", () => {
    renderLogin("/login?error=saml_unavailable");
    expect(screen.getByText(/single sign-on isn't available right now/i)).toBeInTheDocument();
  });
});
