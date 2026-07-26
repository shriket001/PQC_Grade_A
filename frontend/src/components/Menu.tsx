/**
 * Menu — a small, reusable dropdown menu.
 *
 * A trigger (rendered by the caller via a render-prop so it can be any shape —
 * a kebab icon button, an account row, etc.) toggles a popover that lists
 * `items` (or arbitrary `children`). The popover is portaled to `document.body`
 * and positioned fixed against the trigger's rect, so it is never clipped by an
 * ancestor `overflow: auto` container (e.g. the conversation list's scroll
 * region). It closes on outside pointer-down, Escape, or any item selection,
 * and repositions itself on scroll/resize while open. Dismiss pattern mirrors
 * `Modal.tsx`.
 */

import { useId, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

export interface MenuItem {
  label: string;
  onClick: () => void;
  danger?: boolean;
  disabled?: boolean;
}

interface MenuTriggerProps {
  open: boolean;
  /** Spread onto the trigger element so Menu can wire click/aria/ref. */
  triggerProps: {
    onClick: () => void;
    "aria-expanded": boolean;
    "aria-haspopup": "menu";
    "aria-controls": string | undefined;
    ref: (el: HTMLElement | null) => void;
  };
}

interface MenuProps {
  /** Renders the trigger button/row; spread `triggerProps` onto the focusable element. */
  trigger: (props: MenuTriggerProps) => ReactNode;
  /** Structured item list. Mutually exclusive with `children`. */
  items?: MenuItem[];
  /** Align the popover to the trigger's start or end edge. Defaults to "end". */
  align?: "start" | "end";
  ariaLabel: string;
  /** Optional non-interactive header rendered above the items (e.g. account name). */
  header?: ReactNode;
  /** Alternative to `items` for fully custom menu content. */
  children?: ReactNode;
}

const POPOVER_WIDTH = 180;
const POPOVER_MARGIN = 6;
const SCREEN_PAD = 8;

export function Menu({
  trigger,
  items,
  align = "end",
  ariaLabel,
  header,
  children,
}: MenuProps): JSX.Element {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerElRef = useRef<HTMLElement | null>(null);
  const menuId = useId();

  const close = (): void => setOpen(false);
  const toggle = (): void => setOpen((o) => !o);

  function measure(): void {
    const el = triggerElRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    let left = align === "end" ? r.right - POPOVER_WIDTH : r.left;
    const maxLeft = window.innerWidth - POPOVER_WIDTH - SCREEN_PAD;
    if (left < SCREEN_PAD) left = SCREEN_PAD;
    if (left > maxLeft) left = Math.max(SCREEN_PAD, maxLeft);
    // Flip the popover above the trigger when there isn't room below (e.g. the
    // account menu opens from the bottom of the sidebar) — estimate the popover
    // height from its item count so the first placement is correct without a
    // second layout pass.
    const estHeight =
      (items?.length ?? 0) * 38 + (header ? 44 : 0) + 12;
    const bottomSpace = window.innerHeight - r.bottom - POPOVER_MARGIN;
    const top =
      bottomSpace < estHeight && r.top > window.innerHeight / 2
        ? Math.max(SCREEN_PAD, r.top - POPOVER_MARGIN - estHeight)
        : r.bottom + POPOVER_MARGIN;
    setPos({ top, left });
  }

  useLayoutEffect(() => {
    if (!open) return;
    measure();
    // Reposition while open so the popover stays attached to its trigger on
    // scroll (capture so inner scroll containers — e.g. the conversation list —
    // are caught too, since scroll events do not bubble) and viewport resize.
    function onScroll(): void {
      measure();
    }
    function onResize(): void {
      measure();
    }
    function onPointerDown(e: MouseEvent): void {
      const target = e.target as Node | null;
      if (containerRef.current?.contains(target)) return;
      const popover = document.getElementById(menuId);
      if (popover?.contains(target)) return;
      close();
    }
    function onKeyDown(e: KeyboardEvent): void {
      if (e.key === "Escape") close();
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onResize);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onResize);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- measure/close are stable closures; re-subscribing only needs to track `open` + alignment.
  }, [open, align, menuId]);

  function runItem(item: MenuItem): void {
    if (item.disabled) return;
    close();
    item.onClick();
  }

  const triggerProps: MenuTriggerProps["triggerProps"] = {
    onClick: toggle,
    "aria-expanded": open,
    "aria-haspopup": "menu",
    "aria-controls": open ? menuId : undefined,
    ref: (el: HTMLElement | null) => {
      triggerElRef.current = el;
    },
  };

  return (
    <div className="menu" ref={containerRef} data-open={open ? "" : undefined}>
      {trigger({ open, triggerProps })}
      {open && pos
        ? createPortal(
            <div
              id={menuId}
              className={`menu__popover menu__popover--${align}`}
              style={{ position: "fixed", top: pos.top, left: pos.left }}
              role="menu"
              aria-label={ariaLabel}
            >
              {header ? <div className="menu__header">{header}</div> : null}
              {items
                ? items.map((it, i) => (
                    <button
                      key={i}
                      type="button"
                      role="menuitem"
                      className={`menu__item${it.danger ? " menu__item--danger" : ""}`}
                      disabled={it.disabled}
                      onClick={() => runItem(it)}
                    >
                      {it.label}
                    </button>
                  ))
                : children}
            </div>,
            document.body,
          )
        : null}
    </div>
  );
}