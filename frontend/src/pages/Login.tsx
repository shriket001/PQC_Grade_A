import { useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";

import { AuthShell } from "@/components/AuthShell";
import { Button } from "@/components/Button";
import { FormField } from "@/components/FormField";
import { GoogleIcon } from "@/components/GoogleIcon";
import { SsoIcon } from "@/components/SsoIcon";
import { parseUserIdFromAccessToken } from "@/lib/jwt";
import { login } from "@/services/authService";
import { API_BASE_URL, ApiError } from "@/services/apiClient";
import { useAuthStore } from "@/store/authStore";
import { AUTH_ERROR_GUIDANCE, type AuthErrorCode } from "@/types/auth";

interface FromState {
  from?: string;
}

// Matches the backend's default SAML_IDP_NAME (backend/src/core/config.py) —
// the `{idp}` path segment for the one currently-configured SAML IdP.
const SAML_IDP_NAME = "samltest";

/** The only `?error=` values the OIDC or SAML callback/ACS redirects ever use
 * (see backend/src/api/v1/oidc.py and saml.py) — narrowed from the raw query
 * string so an unexpected value can't index `AUTH_ERROR_GUIDANCE` with
 * something absent. */
function ssoErrorFromSearchParams(value: string | null): AuthErrorCode | null {
  return value === "oauth_failed" ||
    value === "oauth_unavailable" ||
    value === "saml_failed" ||
    value === "saml_unavailable"
    ? value
    : null;
}

export default function Login(): JSX.Element {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  // Sticky once the backend first asks for a code (FR-009 step-up) — stays
  // visible even through a subsequent wrong-code attempt, since the account
  // is still MFA-enabled either way; only a fresh email/password change (a
  // different account) should hide it again.
  const [mfaRequired, setMfaRequired] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [searchParams] = useSearchParams();
  // Seeded from `?error=` if the browser just bounced back from a failed
  // Google sign-in redirect (backend/src/api/v1/oidc.py's `_login_redirect`) —
  // a normal page load or password-login attempt has no such param.
  const [errorCode, setErrorCode] = useState<AuthErrorCode | null>(() =>
    ssoErrorFromSearchParams(searchParams.get("error")),
  );

  const navigate = useNavigate();
  const location = useLocation();
  const signIn = useAuthStore((s) => s.signIn);
  const setPendingUnlockPassword = useAuthStore((s) => s.setPendingUnlockPassword);

  async function handleSubmit(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setErrorCode(null);
    setSubmitting(true);
    try {
      const tokens = await login({
        email,
        password,
        totp_code: mfaRequired && totpCode ? totpCode : undefined,
      });
      // The JWT carries only sub/sid, so the username is unknown at login time.
      // Seed it empty; the Conversations bootstrap calls /users/me to fill in
      // the authoritative handle (US2 / FR-052).
      signIn({
        userId: parseUserIdFromAccessToken(tokens.access_token),
        email,
        username: "",
        accessToken: tokens.access_token,
        expiresAt: tokens.expires_at,
      });
      // FR-054: stash the password transiently (in-memory only, never persisted)
      // so the Conversations bootstrap can unwrap — or generate + wrap — the
      // identity without re-prompting. Cleared immediately after bootstrap uses it.
      setPendingUnlockPassword(password);
      const from = (location.state as FromState | null)?.from;
      navigate(from ?? "/", { replace: true });
    } catch (err) {
      const code = err instanceof ApiError ? err.errorCode : "unknown_error";
      setErrorCode(code);
      if (code === "mfa_required" || code === "invalid_mfa_code") {
        setMfaRequired(true);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthShell eyebrow="Welcome back" title="Sign in" subtitle="Your browser holds the keys.">
      <form className="form" onSubmit={handleSubmit} noValidate>
        {errorCode ? (
          <div className="alert" role="alert">
            <span className="alert__label">Error</span>
            <span>
              {AUTH_ERROR_GUIDANCE[errorCode]}
              {errorCode === "email_not_verified" ? (
                <>
                  {" "}
                  <Link to="/verify-email">Enter your verification token</Link>
                </>
              ) : null}
            </span>
          </div>
        ) : null}

        <FormField
          label="Email"
          name="email"
          type="email"
          autoComplete="email"
          required
          placeholder="you@example.com"
          value={email}
          invalid={errorCode === "invalid_credentials"}
          onChange={(e) => setEmail(e.target.value)}
        />

        <FormField
          label="Password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          placeholder="Your password"
          value={password}
          invalid={errorCode === "invalid_credentials"}
          onChange={(e) => setPassword(e.target.value)}
        />

        {mfaRequired ? (
          <FormField
            label="Authenticator code"
            name="totpCode"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            required
            placeholder="6-digit code"
            value={totpCode}
            mono
            invalid={errorCode === "invalid_mfa_code"}
            onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            autoFocus
          />
        ) : null}

        <Button type="submit" loading={submitting}>
          Sign in
        </Button>
      </form>

      <div className="auth-divider" role="separator">
        <span>or</span>
      </div>

      {/* A real page navigation, not a fetch — OAuth requires a top-level
          redirect to Google's own consent screen. The callback sets the
          refresh cookie and redirects back to "/", where AuthBootstrap
          silently mints an access token from it; see oidc.py's docstring. */}
      <a href={`${API_BASE_URL}/auth/oidc/google/authorize`} className="btn btn--ghost btn--block">
        <GoogleIcon />
        Sign in with Google
      </a>

      {/* Same rationale as the Google link above — a real navigation, not a
          fetch. The IdP's own page then POSTs the SAML assertion straight to
          the backend's /acs endpoint; see saml.py's docstring. */}
      <a
        href={`${API_BASE_URL}/auth/saml/${SAML_IDP_NAME}/login`}
        className="btn btn--ghost btn--block"
        style={{ marginTop: "0.6rem" }}
      >
        <SsoIcon />
        Sign in with SSO
      </a>

      <div className="form-footer">
        No account yet? <Link to="/register">Create one</Link>
      </div>
    </AuthShell>
  );
}
