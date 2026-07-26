import { beforeEach, describe, expect, it, vi } from "vitest";

import { setAccessToken } from "@/services/apiClient";
import { useAuthStore, type AuthSession } from "@/store/authStore";

const futureIso = new Date(Date.now() + 60_000).toISOString();
const pastIso = new Date(Date.now() - 60_000).toISOString();

function makeSession(expiresAt: string): AuthSession {
  return {
    userId: "u-1",
    email: "alice@example.com",
    username: "alice",
    accessToken: "a.b.c",
    expiresAt,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "OK",
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

beforeEach(() => {
  localStorage.clear();
  setAccessToken(null);
  useAuthStore.getState().signOut();
  // signOut() intentionally doesn't touch `bootstrapped` (a real signOut
  // mid-session should stay bootstrapped) — reset it directly so each test
  // starts fresh, as if this were a brand-new page load.
  useAuthStore.setState({ bootstrapped: false });
  vi.unstubAllGlobals();
});

describe("authStore", () => {
  it("isAuthenticated is false with no session", () => {
    expect(useAuthStore.getState().isAuthenticated()).toBe(false);
    expect(useAuthStore.getState().session).toBeNull();
  });

  it("signIn stores the session and mirrors the access token onto the apiClient", () => {
    useAuthStore.getState().signIn(makeSession(futureIso));

    const state = useAuthStore.getState();
    expect(state.session).not.toBeNull();
    expect(state.session?.accessToken).toBe("a.b.c");
    expect(state.isAuthenticated()).toBe(true);
  });

  it("isAuthenticated is false once the access token expiry is in the past", () => {
    useAuthStore.getState().signIn(makeSession(pastIso));
    expect(useAuthStore.getState().isAuthenticated()).toBe(false);
  });

  it("signOut clears the session", () => {
    useAuthStore.getState().signIn(makeSession(futureIso));
    useAuthStore.getState().signOut();
    expect(useAuthStore.getState().session).toBeNull();
    expect(useAuthStore.getState().isAuthenticated()).toBe(false);
  });

  it("signIn never writes the session to localStorage (in-memory only, US10/FR-005)", () => {
    useAuthStore.getState().signIn(makeSession(futureIso));
    expect(localStorage.getItem("vayunx.auth")).toBeNull();
    expect(localStorage.length).toBe(0);
  });

  it("signIn marks the session bootstrapped (no redundant restore needed)", () => {
    useAuthStore.getState().signIn(makeSession(futureIso));
    expect(useAuthStore.getState().bootstrapped).toBe(true);
  });

  it("loadProfile merges the authoritative username + email from /users/me", async () => {
    useAuthStore.getState().signIn({
      userId: "u-1",
      email: "seed@example.com",
      username: "",
      accessToken: "a.b.c",
      expiresAt: futureIso,
    });

    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, {
        id: "u-1",
        username: "realhandle",
        display_name: "realhandle",
        email: "real@example.com",
        email_verified: true,
        created_at: "2030-01-01T00:00:00Z",
        mfa_enabled: true,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await useAuthStore.getState().loadProfile();

    const session = useAuthStore.getState().session;
    expect(session?.username).toBe("realhandle");
    expect(session?.email).toBe("real@example.com");
    expect(session?.mfaEnabled).toBe(true);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/users/me");
  });

  it("refreshMfaStatus updates only mfaEnabled from a fresh /users/me call", async () => {
    useAuthStore.getState().signIn(makeSession(futureIso));
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(200, {
          id: "u-1",
          username: "alice",
          display_name: "alice",
          email: "alice@example.com",
          email_verified: true,
          created_at: "2030-01-01T00:00:00Z",
          mfa_enabled: true,
        }),
      ),
    );

    await useAuthStore.getState().refreshMfaStatus();

    const session = useAuthStore.getState().session;
    expect(session?.mfaEnabled).toBe(true);
    expect(session?.username).toBe("alice"); // untouched, still the seeded value
  });

  it("loadProfile is best-effort and leaves the session intact on failure", async () => {
    useAuthStore.getState().signIn(makeSession(futureIso));
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(500, null)));

    await useAuthStore.getState().loadProfile();

    const session = useAuthStore.getState().session;
    expect(session).not.toBeNull();
    expect(session?.username).toBe("alice");
  });

  it("refreshSession swaps in the rotated access token on success", async () => {
    useAuthStore.getState().signIn(makeSession(pastIso));
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(200, {
          access_token: "new.access.token",
          token_type: "Bearer",
          expires_at: futureIso,
        }),
      ),
    );

    const ok = await useAuthStore.getState().refreshSession();

    expect(ok).toBe(true);
    const session = useAuthStore.getState().session;
    expect(session?.accessToken).toBe("new.access.token");
    expect(useAuthStore.getState().isAuthenticated()).toBe(true);
  });

  it("refreshSession signs out and returns false when the backend rejects the refresh token", async () => {
    useAuthStore.getState().signIn(makeSession(pastIso));
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(401, { error_code: "invalid_refresh_token", message: "dead" }),
      ),
    );

    const ok = await useAuthStore.getState().refreshSession();

    expect(ok).toBe(false);
    expect(useAuthStore.getState().session).toBeNull();
  });

  it("refreshSession is a no-op returning false when there is no session", async () => {
    const ok = await useAuthStore.getState().refreshSession();
    expect(ok).toBe(false);
  });

  describe("restoreSession (app-boot silent sign-in)", () => {
    it("redeems the refresh cookie into a fresh session and fills the profile", async () => {
      const fetchMock = vi
        .fn()
        // 1st call: POST /auth/refresh
        .mockResolvedValueOnce(
          jsonResponse(200, {
            access_token: "a.b.c",
            token_type: "Bearer",
            expires_at: futureIso,
          }),
        )
        // 2nd call: GET /users/me (loadProfile, chained inside restoreSession)
        .mockResolvedValueOnce(
          jsonResponse(200, {
            id: "u-1",
            username: "restored",
            display_name: "restored",
            email: "restored@example.com",
            email_verified: true,
            created_at: "2030-01-01T00:00:00Z",
            mfa_enabled: false,
          }),
        );
      vi.stubGlobal("fetch", fetchMock);

      expect(useAuthStore.getState().bootstrapped).toBe(false);
      await useAuthStore.getState().restoreSession();

      expect(useAuthStore.getState().bootstrapped).toBe(true);
      const session = useAuthStore.getState().session;
      expect(session?.accessToken).toBe("a.b.c");
      expect(session?.username).toBe("restored");
      expect(useAuthStore.getState().isAuthenticated()).toBe(true);
      expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/auth/refresh");
    });

    it("leaves session null but still marks bootstrapped when there's no valid cookie", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(401, { error_code: "unauthenticated", message: "missing refresh token" }),
        ),
      );

      await useAuthStore.getState().restoreSession();

      expect(useAuthStore.getState().bootstrapped).toBe(true);
      expect(useAuthStore.getState().session).toBeNull();
      expect(useAuthStore.getState().isAuthenticated()).toBe(false);
    });

    it("is a no-op on a second call once already bootstrapped", async () => {
      const fetchMock = vi.fn().mockResolvedValue(jsonResponse(401, { error_code: "unauthenticated" }));
      vi.stubGlobal("fetch", fetchMock);

      await useAuthStore.getState().restoreSession();
      await useAuthStore.getState().restoreSession();

      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });
});