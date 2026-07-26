/**
 * Auth session store (zustand, in-memory only — no `persist` middleware).
 *
 * Holds the credential bundle returned by `/auth/login` plus the user's public
 * handle (`username`), so the app can render a signed-in shell. The JWT only
 * carries `sub`/`sid`, so the username is unknown at login time and is seeded
 * empty; `loadProfile()` pulls the authoritative handle (and email) from
 * `/users/me` — the correct, non-workaround flow. The access token is mirrored
 * into the `apiClient` bearer header so every authenticated request carries it.
 *
 * US10/FR-005 (fully hardened): NEITHER credential ever touches `localStorage`.
 * The refresh token lives solely in the HttpOnly cookie `apiClient` round-trips
 * via `credentials: "include"` — no client-side JS can ever read it. The
 * access token now lives only in this in-memory store — a page reload starts
 * with `session: null` and `restoreSession()` (called once at app boot, see
 * `AuthBootstrap.tsx`) silently redeems the refresh cookie for a fresh access
 * token, exactly like a real login, before anything protected renders.
 */

import { create } from "zustand";

import { parseUserIdFromAccessToken } from "@/lib/jwt";
import * as authService from "@/services/authService";
import { setAccessToken, setUnauthorizedHandler } from "@/services/apiClient";
import { fetchProfile } from "@/services/userService";

export interface AuthSession {
  userId: string;
  email: string;
  /** Public handle; empty until `loadProfile()` resolves `/users/me`. */
  username: string;
  accessToken: string;
  expiresAt: string; // ISO 8601
  /** Whether TOTP MFA is active on this account (FR-009); undefined until
   * `loadProfile()` resolves `/users/me`. */
  mfaEnabled?: boolean;
}

interface AuthState {
  session: AuthSession | null;
  /**
   * True once the app-boot `restoreSession()` attempt has resolved (whether it
   * found a valid refresh cookie or not) — `RequireAuth`/`AuthBootstrap` wait
   * on this before deciding to render the app or bounce to `/login`, so a
   * still-valid session isn't mistaken for "signed out" during that first,
   * necessarily-async check.
   */
  bootstrapped: boolean;
  /**
   * Transient password captured at login, consumed once by the messaging
   * bootstrap to unwrap (or generate+wrap) the identity (FR-054). Lives only
   * in memory for the login→bootstrap handoff so a fresh browser can recover
   * the wrapped identity without re-prompting for the password the user just
   * typed. (On a `restoreSession()`-recovered session — e.g. after a reload —
   * this is never set, so the identity vault's own "enter password to unlock"
   * prompt takes over instead, exactly as it already does today.)
   */
  pendingUnlockPassword: string | null;
  /** Set after a successful login. Returns void for convenience in pages. */
  signIn: (session: AuthSession) => void;
  /** Stash the login password for the bootstrap to consume (then clear). */
  setPendingUnlockPassword: (password: string | null) => void;
  /** Resolve `/users/me` and merge the authoritative username + email in. */
  loadProfile: () => Promise<void>;
  /** Re-resolve `/users/me` and refresh only `mfaEnabled` (see impl below). */
  refreshMfaStatus: () => Promise<void>;
  /** Clear all session state (logout, expired token, hard navigation). */
  signOut: () => void;
  /** True when an access token is present and not past its expiry. */
  isAuthenticated: () => boolean;
  /**
   * Redeem the current refresh token for a new access+refresh pair, called by
   * `apiClient` (via `setUnauthorizedHandler` below) when a request 401s.
   * Returns false — after clearing the session — if there's nothing to
   * refresh or the backend rejects the refresh token (expired/already
   * rotated/revoked by a logout elsewhere), so the caller knows to bounce the
   * user back to sign-in instead of retrying.
   */
  refreshSession: () => Promise<boolean>;
  /**
   * App-boot silent sign-in: redeems the HttpOnly refresh cookie (if any) for
   * a fresh access token, without any password/credentials in hand — this is
   * what replaces reading a persisted access token out of `localStorage`.
   * Idempotent and safe to call more than once; always resolves (never
   * throws) and always ends by setting `bootstrapped: true`.
   */
  restoreSession: () => Promise<void>;
}

// React 18 StrictMode (dev only) double-invokes effects, so `AuthBootstrap`'s
// `useEffect` calls `restoreSession()` twice back-to-back, before the first
// call's `set({ bootstrapped: true })` has landed — the in-store guard below
// can't see it yet. Without this, both calls redeem the same (single-use,
// rotate-on-use) refresh cookie concurrently; whichever request the backend
// processes second gets back "already rotated" and 401s. Sharing one in-flight
// promise across both calls, the same pattern `apiClient.ts` uses for 401-
// triggered refreshes, means only one `/auth/refresh` request is ever sent.
let restoreSessionInFlight: Promise<void> | null = null;

export const useAuthStore = create<AuthState>()((set, get) => ({
  session: null,
  bootstrapped: false,
  pendingUnlockPassword: null,
  signIn: (session) => {
    setAccessToken(session.accessToken);
    set({ session, bootstrapped: true });
  },
  setPendingUnlockPassword: (password) => {
    set({ pendingUnlockPassword: password });
  },
  loadProfile: async () => {
    const session = get().session;
    if (!session) return;
    // Best-effort: the app keeps working with the JWT-seeded session even if
    // this call fails (e.g. transient network). The username/email simply
    // stay as seeded.
    try {
      const profile = await fetchProfile();
      set({
        session: {
          ...session,
          username: profile.username,
          email: profile.email,
          mfaEnabled: profile.mfa_enabled,
        },
      });
    } catch {
      // Intentionally swallowed — see note above.
    }
  },
  /** Re-resolve `/users/me` and flip only `mfaEnabled` — called after a
   * successful enroll/disable so the settings UI reflects it immediately
   * without waiting for the next full profile refresh. */
  refreshMfaStatus: async () => {
    const session = get().session;
    if (!session) return;
    try {
      const profile = await fetchProfile();
      set((s) => (s.session ? { session: { ...s.session, mfaEnabled: profile.mfa_enabled } } : s));
    } catch {
      // Best-effort — the caller (MfaSettingsModal) already knows the
      // outcome of its own enroll/disable call regardless.
    }
  },
  signOut: () => {
    setAccessToken(null);
    set({ session: null, pendingUnlockPassword: null });
  },
  isAuthenticated: () => {
    const session = get().session;
    if (!session) return false;
    return Date.parse(session.expiresAt) > Date.now();
  },
  refreshSession: async () => {
    // Fast-path guard: nothing to refresh if this tab never signed in —
    // the actual refresh token lives only in the HttpOnly cookie, so
    // `authService.refresh()` itself needs no session-derived argument.
    if (!get().session) return false;
    try {
      const tokens = await authService.refresh();
      // Re-read the session rather than closing over the outer guard: a
      // concurrent signOut() while this refresh was in flight must not
      // resurrect a session the user (or another 401) just cleared.
      const current = get().session;
      if (!current) return false;
      set({
        session: {
          ...current,
          accessToken: tokens.access_token,
          expiresAt: tokens.expires_at,
        },
      });
      return true;
    } catch {
      // Dead/expired/already-rotated refresh token — no way to recover
      // this session; clear it so the app routes back to sign-in.
      get().signOut();
      return false;
    }
  },
  restoreSession: async () => {
    if (get().bootstrapped) return;
    if (restoreSessionInFlight) return restoreSessionInFlight;
    restoreSessionInFlight = (async () => {
      try {
        const tokens = await authService.refresh();
        set({
          session: {
            userId: parseUserIdFromAccessToken(tokens.access_token),
            email: "",
            username: "",
            accessToken: tokens.access_token,
            expiresAt: tokens.expires_at,
          },
        });
        // Best-effort fill-in of username/email/mfaEnabled; isAuthenticated()
        // above already reflects the restored session regardless of this
        // resolving. Errors are swallowed inside loadProfile itself.
        await get().loadProfile();
      } catch {
        // No valid refresh cookie (never logged in on this browser, or the
        // cookie expired/was revoked elsewhere) — session stays null, and
        // RequireAuth sends the user to /login exactly as if freshly signed out.
      } finally {
        set({ bootstrapped: true });
        restoreSessionInFlight = null;
      }
    })();
    return restoreSessionInFlight;
  },
}));

// Wired here (not in apiClient, which the store already imports — the
// reverse import would be circular) so a 401 on ANY apiClient call transparently
// redeems the stored refresh token instead of surfacing as a hard logout.
setUnauthorizedHandler(() => useAuthStore.getState().refreshSession());
