/** Modal — a centered dialog overlay (Escape + backdrop-click to dismiss). */

import { useEffect } from "react";
import { createPortal } from "react-dom";

interface ModalProps {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  /** Disable dismissal (backdrop click / Escape) while a submission is in flight. */
  dismissDisabled?: boolean;
  /** Dialog width. Defaults to "md". */
  size?: "sm" | "md" | "lg";
}

export function Modal({
  title,
  onClose,
  children,
  dismissDisabled = false,
  size = "md",
}: ModalProps): JSX.Element {
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent): void {
      if (e.key === "Escape" && !dismissDisabled) onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose, dismissDisabled]);

  return createPortal(
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !dismissDisabled) onClose();
      }}
    >
      <div className={`modal modal--${size}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal__head">
          <h2 className="modal__title">{title}</h2>
          <button
            type="button"
            className="modal__close"
            onClick={onClose}
            disabled={dismissDisabled}
            aria-label="Close dialog"
          >
            ×
          </button>
        </div>
        <div className="modal__body">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
