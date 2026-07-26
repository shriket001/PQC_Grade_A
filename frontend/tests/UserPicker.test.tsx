/**
 * @jest-environment jsdom
 */
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { UserPicker } from "@/components/UserPicker";
import { setAccessToken } from "@/services/apiClient";
import type { UserSummaryResponse } from "@/types/user";

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
  vi.restoreAllMocks();
});

function Harness(props: { mode: "single" | "multi"; excludeIds?: string[] }) {
  const [selected, setSelected] = useState<UserSummaryResponse[]>([]);
  return (
    <UserPicker
      mode={props.mode}
      label="Members"
      selected={selected}
      onChange={setSelected}
      excludeIds={props.excludeIds}
    />
  );
}

describe("UserPicker", () => {
  it("does not search below the 2-character minimum", async () => {
    render(<Harness mode="single" />);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "b" } });
    expect(screen.getByText(/type at least 2 characters/i)).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows matching users in a dropdown after typing, and selects one on click (single mode)", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, [
        { id: "bob-id", username: "bob", display_name: "Bob" },
        { id: "bobby-id", username: "bobby", display_name: "Bobby" },
      ]),
    );
    render(<Harness mode="single" />);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "bo" } });

    await waitFor(() => expect(screen.getByText("bob")).toBeInTheDocument());
    expect(screen.getByText("bobby")).toBeInTheDocument();

    fireEvent.mouseDown(screen.getByText("bob"));

    // Single mode replaces the input with a removable chip for the choice.
    await waitFor(() => expect(screen.queryByRole("combobox")).not.toBeInTheDocument());
    expect(screen.getByText("bob")).toBeInTheDocument();
  });

  it("supports multi-select: selecting twice keeps both as chips and excludes them from further results", async () => {
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes("q=bo")) {
        return jsonResponse(200, [
          { id: "bob-id", username: "bob", display_name: "Bob" },
          { id: "bobby-id", username: "bobby", display_name: "Bobby" },
        ]);
      }
      return jsonResponse(200, []);
    });
    render(<Harness mode="multi" />);
    const input = screen.getByRole("combobox");

    fireEvent.change(input, { target: { value: "bo" } });
    await waitFor(() => expect(screen.getByText("bob")).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByText("bob"));

    // The combobox stays present (multi mode), input cleared, chip added.
    expect(screen.getByRole("combobox")).toBeInTheDocument();
    expect(screen.getAllByText("bob").length).toBeGreaterThanOrEqual(1);

    fireEvent.change(screen.getByRole("combobox"), { target: { value: "bo" } });
    await waitFor(() => expect(screen.getByText("bobby")).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByText("bobby"));

    expect(screen.getByText("bob")).toBeInTheDocument();
    expect(screen.getByText("bobby")).toBeInTheDocument();
  });

  it("removes a chip when its × button is clicked (multi mode)", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, [{ id: "bob-id", username: "bob", display_name: "Bob" }]),
    );
    render(<Harness mode="multi" />);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "bob" } });
    await waitFor(() => expect(screen.getByText("bob")).toBeInTheDocument());
    fireEvent.mouseDown(screen.getByText("bob"));

    const removeBtn = await screen.findByLabelText("Remove bob");
    fireEvent.click(removeBtn);
    expect(screen.queryByLabelText("Remove bob")).not.toBeInTheDocument();
  });

  it("shows a 'no matching users' state when the search returns nothing", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, []));
    render(<Harness mode="single" />);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "zzz" } });
    await waitFor(() => expect(screen.getByText(/no matching users/i)).toBeInTheDocument());
  });
});
