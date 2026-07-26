/**
 * AuthBootstrap — app-boot gate for the in-memory-only access token (US10/FR-005).
 *
 * Since the access token is no longer persisted to `localStorage`, a hard
 * reload always starts with `session: null`. Without this gate, `RequireAuth`
 * would see "no session" on that very first render and bounce a still-signed-in
 * user to `/login` before `restoreSession()` (which redeems the HttpOnly
 * refresh cookie) even gets a chance to run. This component runs that redemption
 * once, up front, and holds rendering until it resolves either way.
 */

import { useEffect } from "react";
import type { ReactNode } from "react";

import { useAuthStore } from "@/store/authStore";

export function AuthBootstrap({ children }: { children: ReactNode }): JSX.Element {
  const bootstrapped = useAuthStore((s) => s.bootstrapped);
  const restoreSession = useAuthStore((s) => s.restoreSession);

  useEffect(() => {
    void restoreSession();
  }, [restoreSession]);

  if (!bootstrapped) {
    return (
      <div className="app-boot" role="status" aria-label="Loading">
        <span className="app-boot__spinner" aria-hidden="true" />
      </div>
    );
  }
  return <>{children}</>;
}
