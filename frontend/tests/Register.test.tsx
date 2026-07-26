/**
 * @jest-environment jsdom
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Register from "@/pages/Register";

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
});

afterEach(() => {
  vi.restoreAllMocks();
});

function renderRegister() {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Register />
    </MemoryRouter>,
  );
}

describe("Register page", () => {
  it("renders the three required fields", () => {
    renderRegister();
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create account/i })).toBeInTheDocument();
  });

  it("shows the post-registration state on a 201", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(201, { user_id: "u", username: "alice", status: "unverified" }),
    );
    renderRegister();

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "alice@example.com" } });
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Sup3rSecret!" } });
    fireEvent.click(screen.getByRole("button", { name: /create account/i }));

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /check your inbox/i })).toBeInTheDocument();
    });
    expect(screen.getByText("alice@example.com")).toBeInTheDocument();

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/auth/register");
    expect(JSON.parse(init.body as string)).toEqual({
      email: "alice@example.com",
      password: "Sup3rSecret!",
      username: "alice",
    });
  });

  it("maps username_taken to user-facing guidance", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(409, { error_code: "username_taken", message: "taken" }),
    );
    renderRegister();

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "dup@example.com" } });
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "dup" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Sup3rSecret!" } });
    fireEvent.click(screen.getByRole("button", { name: /create account/i }));

    await waitFor(() => {
      expect(screen.getByText(/That username is taken/i)).toBeInTheDocument();
    });
    // Still on the form (no success heading).
    expect(screen.queryByRole("heading", { name: /check your inbox/i })).not.toBeInTheDocument();
  });

  it("maps email_already_registered to user-facing guidance without crashing", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(409, { error_code: "email_already_registered", message: "exists" }),
    );
    renderRegister();

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "dup@example.com" } });
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "dup" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Sup3rSecret!" } });
    fireEvent.click(screen.getByRole("button", { name: /create account/i }));

    await waitFor(() => {
      expect(
        screen.getByText(/An account already exists for this email/i),
      ).toBeInTheDocument();
    });
    // Still on the form (no success heading).
    expect(screen.queryByRole("heading", { name: /check your inbox/i })).not.toBeInTheDocument();
  });
});