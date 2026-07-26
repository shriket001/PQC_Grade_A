/**
 * @jest-environment jsdom
 */
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import { Menu, type MenuItem } from "@/components/Menu";

function renderMenu(items: MenuItem[] = [{ label: "Delete chat", onClick: vi.fn(), danger: true }]) {
  render(
    <Menu
      ariaLabel="Actions"
      items={items}
      trigger={({ triggerProps }) => (
        <button type="button" {...triggerProps}>
          More
        </button>
      )}
    />,
  );
  return { trigger: screen.getByRole("button", { name: "More" }) };
}

describe("Menu", () => {
  it("opens on trigger click and exposes its items", () => {
    const { trigger } = renderMenu();
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    fireEvent.click(trigger);
    expect(screen.getByRole("menu")).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Delete chat" })).toBeInTheDocument();
    expect(trigger).toHaveAttribute("aria-expanded", "true");
  });

  it("runs the item onClick and closes after selecting it", () => {
    const onClick = vi.fn();
    const { trigger } = renderMenu([{ label: "Delete chat", onClick }]);
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole("menuitem", { name: "Delete chat" }));
    expect(onClick).toHaveBeenCalledOnce();
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("closes on Escape", () => {
    const { trigger } = renderMenu();
    fireEvent.click(trigger);
    expect(screen.getByRole("menu")).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("closes on an outside pointer-down", () => {
    const { trigger } = renderMenu();
    fireEvent.click(trigger);
    expect(screen.getByRole("menu")).toBeInTheDocument();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("marks a danger item with the danger class", () => {
    const { trigger } = renderMenu([
      { label: "Delete chat", onClick: vi.fn(), danger: true },
      { label: "Open", onClick: vi.fn() },
    ]);
    fireEvent.click(trigger);
    const danger = screen.getByRole("menuitem", { name: "Delete chat" });
    const normal = screen.getByRole("menuitem", { name: "Open" });
    expect(danger).toHaveClass("menu__item--danger");
    expect(normal).not.toHaveClass("menu__item--danger");
  });
});