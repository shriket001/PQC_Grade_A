import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { AuthShell } from "@/components/AuthShell";
import { Button } from "@/components/Button";
import { FormField } from "@/components/FormField";
import { SuccessIcon } from "@/components/SuccessIcon";
import { verifyEmail } from "@/services/authService";
import { ApiError } from "@/services/apiClient";
import { AUTH_ERROR_GUIDANCE, type AuthErrorCode } from "@/types/auth";

type Phase = "idle" | "verifying" | "verified" | "error";

export default function VerifyEmail(): JSX.Element {
  const [params] = useSearchParams();
  const initialToken = params.get("token") ?? "";

  const [token, setToken] = useState(initialToken);
  const [phase, setPhase] = useState<Phase>(initialToken ? "verifying" : "idle");
  const [errorCode, setErrorCode] = useState<AuthErrorCode | null>(null);

  const runVerification = useCallback(async (value: string): Promise<void> => {
    setErrorCode(null);
    setPhase("verifying");
    try {
      await verifyEmail({ verification_token: value });
      setPhase("verified");
    } catch (err) {
      setErrorCode(err instanceof ApiError ? err.errorCode : "unknown_error");
      setPhase("error");
    }
  }, []);

  // Auto-verify once when the email link supplies a token in the URL.
  useEffect(() => {
    if (initialToken) {
      void runVerification(initialToken);
    }
  }, [initialToken, runVerification]);

  function handleSubmit(event: React.FormEvent): void {
    event.preventDefault();
    if (token.trim()) {
      void runVerification(token.trim());
    }
  }

  if (phase === "verified") {
    return (
      <AuthShell eyebrow="Email confirmed" title="You're verified">
        <SuccessIcon />
        <div className="alert alert--ok">
          <span className="alert__label">Done</span>
          <span>Your email is confirmed. You can sign in now.</span>
        </div>
        <div className="form" style={{ marginTop: "1.25rem" }}>
          <Link to="/login" className="btn btn--primary">
            Sign in
          </Link>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      eyebrow="Confirm your address"
      title="Verify your email"
      subtitle={
        initialToken
          ? undefined
          : "Paste the verification token from your email, or open the link in the email directly."
      }
    >
      <form className="form" onSubmit={handleSubmit} noValidate>
        {phase === "error" && errorCode ? (
          <div className="alert" role="alert">
            <span className="alert__label">Error</span>
            <span>
              {AUTH_ERROR_GUIDANCE[errorCode]} <Link to="/register">Create a new account</Link>
            </span>
          </div>
        ) : null}

        <FormField
          label="Verification token"
          name="verification_token"
          mono
          autoComplete="off"
          required
          placeholder="paste the token from your email"
          value={token}
          invalid={phase === "error"}
          onChange={(e) => setToken(e.target.value)}
        />

        <Button type="submit" loading={phase === "verifying"}>
          Verify email
        </Button>
      </form>
      <div className="form-footer">
        <Link to="/login">Back to sign in</Link>
      </div>
    </AuthShell>
  );
}
