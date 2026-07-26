import type { ReactNode } from "react";

import { LatticeField } from "@/components/LatticeField";
import { ThemeToggle } from "@/components/ThemeToggle";

interface AuthShellProps {
  /** Eyebrow above the title, e.g. "Create your account". */
  eyebrow: string;
  title: string;
  subtitle?: ReactNode;
  children: ReactNode;
  /** Optional content under the form (links to other auth pages). */
  footer?: ReactNode;
}

/**
 * Two-pane auth surface. The left thesis panel carries the lattice signature
 * and the secure-channel narrative; the right pane holds the form. On narrow
 * screens the thesis collapses away and the lattice becomes a quiet background
 * behind a single card.
 */
export function AuthShell({
  eyebrow,
  title,
  subtitle,
  children,
  footer,
}: AuthShellProps): JSX.Element {
  return (
    <div className="app-shell">
      <aside className="shell-thesis" aria-hidden="true">
        <LatticeField variant="feature" />
        <div className="thesis-top">
          <div className="thesis-top-row">
            <span className="wordmark">
              VAYUNX<span className="wordmark__grade">GRADE&nbsp;A</span>
            </span>
          </div>
          <h1 className="thesis-headline">
            Encrypted chat, <em>post-quantum</em> by default.
          </h1>
          <p className="thesis-body">
            Messages and files are sealed in your browser with lattice-based cryptography. The
            server only ever relays ciphertext — it can never read your conversations.
          </p>
        </div>
        <div className="thesis-bottom">
          <div className="thesis-status">
            <div className="status-row">
              <span className="status-dot status-dot--live" />
              <span>
                <strong>Key exchange</strong> · ML-KEM-768
              </span>
            </div>
            <div className="status-row">
              <span className="status-dot status-dot--live" />
              <span>
                <strong>Identity signatures</strong> · ML-DSA-65
              </span>
            </div>
            <div className="status-row">
              <span className="status-dot" />
              <span>
                <strong>Message cipher</strong> · AES-256-GCM
              </span>
            </div>
          </div>
          <div className="fingerprint">
            <span className="fingerprint__label">Session key fingerprint</span>
            <span className="fingerprint__value">
              4f9a · 2c71 · b8e0 · 6d33 · a14f · 9e27 · 0b5c · 88fa
            </span>
          </div>
        </div>
      </aside>

      <main className="shell-form">
        <div className="shell-form-toggle">
          <ThemeToggle />
        </div>
        <div className="card">
          <div className="card__mobile-wordmark">
            VAYUNX<span className="wordmark__grade">GRADE&nbsp;A</span>
          </div>
          <p className="eyebrow card__eyebrow">{eyebrow}</p>
          <h2 className="card__title">{title}</h2>
          {subtitle ? <p className="card__subtitle">{subtitle}</p> : null}
          {children}
          {footer ? <div className="form-footer">{footer}</div> : null}
        </div>
      </main>
    </div>
  );
}
