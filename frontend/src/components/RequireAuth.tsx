import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { useAuthStore } from "@/store/authStore";

/**
 * Route guard. Redirects to /login (remembering where the user was headed) when
 * there is no valid (present + unexpired) session. The expiry check is
 * client-side advisory only — the backend re-validates the signed token and
 * DB session on every protected call (defense in depth, Phase 4 report).
 */
export function RequireAuth({ children }: { children: ReactNode }): JSX.Element {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const location = useLocation();

  if (!isAuthenticated()) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}
