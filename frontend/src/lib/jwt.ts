/**
 * Best-effort user id from a compact JWS access token's `sub` claim, for
 * display only. The backend remains the source of truth; `/users/me` (US2)
 * is the authoritative profile fetch. Falls back to "unknown" if the token
 * isn't the expected shape — never throws, never blocks a caller.
 */
export function parseUserIdFromAccessToken(token: string): string {
  try {
    const payload = token.split(".")[1];
    const json = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    return typeof json.sub === "string" ? json.sub : "unknown";
  } catch {
    return "unknown";
  }
}
