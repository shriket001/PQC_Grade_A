import { useState } from "react";
import { Link } from "react-router-dom";

import { AuthShell } from "@/components/AuthShell";
import { Button } from "@/components/Button";
import { FormField } from "@/components/FormField";
import { SuccessIcon } from "@/components/SuccessIcon";
import { register } from "@/services/authService";
import { ApiError } from "@/services/apiClient";
import { AUTH_ERROR_GUIDANCE, type AuthErrorCode } from "@/types/auth";

interface Strength {
  score: number; // 0..4
  label: string;
  meets: boolean;
}

function scorePassword(pw: string): Strength {
  let score = 0;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw)) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  const meets = score === 4;
  const labels = ["too short", "weak", "fair", "good", "strong"];
  return { score, label: labels[score], meets };
}

export default function Register(): JSX.Element {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [errorCode, setErrorCode] = useState<AuthErrorCode | null>(null);
  const [registeredEmail, setRegisteredEmail] = useState<string | null>(null);

  const strength = scorePassword(password);

  async function handleSubmit(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setErrorCode(null);
    setSubmitting(true);
    try {
      await register({ email, password, username });
      setRegisteredEmail(email);
    } catch (err) {
      setErrorCode(err instanceof ApiError ? err.errorCode : "unknown_error");
    } finally {
      setSubmitting(false);
    }
  }

  if (registeredEmail) {
    return (
      <AuthShell
        eyebrow="Account created"
        title="Check your inbox"
        subtitle={
          <>
            We sent a verification link to <strong className="mono">{registeredEmail}</strong>. Open
            it to confirm your address, then sign in.
          </>
        }
      >
        <SuccessIcon />
        <div className="alert alert--ok">
          <span className="alert__label">Pending</span>
          <span>
            Your account is registered but not yet verified. You can sign in once you confirm your
            email.
          </span>
        </div>
        <div className="form" style={{ marginTop: "1.25rem" }}>
          <Link to="/login" className="btn btn--primary">
            Continue to sign in
          </Link>
          <Link to="/verify-email" className="btn btn--ghost">
            Enter a verification token
          </Link>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      eyebrow="Create your account"
      title="Sign up"
      subtitle="Encryption keys are generated in your browser after you verify your email."
    >
      <form className="form" onSubmit={handleSubmit} noValidate>
        {errorCode ? (
          <div className="alert" role="alert">
            <span className="alert__label">Error</span>
            <span>{AUTH_ERROR_GUIDANCE[errorCode]}</span>
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
          invalid={errorCode === "email_already_registered"}
          onChange={(e) => setEmail(e.target.value)}
        />

        <FormField
          label="Username"
          name="username"
          autoComplete="username"
          required
          minLength={3}
          maxLength={32}
          pattern="^[a-zA-Z0-9_]{3,32}$"
          placeholder="How others will find you"
          value={username}
          invalid={errorCode === "username_taken"}
          hint="3–32 characters: letters, digits, and underscore. This is how others start a chat with you."
          onChange={(e) => setUsername(e.target.value)}
        />

        <div>
          <FormField
            label="Password"
            name="password"
            type="password"
            autoComplete="new-password"
            required
            placeholder="At least 12 characters"
            value={password}
            invalid={errorCode === "weak_password"}
            onChange={(e) => setPassword(e.target.value)}
          />
          {password ? (
            <div className="field__hint" style={{ marginTop: "0.4rem" }}>
              <div className="meter" aria-hidden="true" style={{ marginBottom: "0.35rem" }}>
                <span
                  className={`meter__bar meter__bar--${strength.score}`}
                  style={{ width: `${(strength.score / 4) * 100}%` }}
                />
              </div>
              <span className="mono" style={{ textTransform: "capitalize" }}>
                {strength.label}
              </span>
              <span> · lowercase, uppercase, digit, 12+ characters</span>
            </div>
          ) : (
            <span className="field__hint" style={{ marginTop: "0.35rem" }}>
              Lowercase, uppercase, digit, and at least 12 characters.
            </span>
          )}
        </div>

        <Button type="submit" loading={submitting}>
          Create account
        </Button>
      </form>
      <div className="form-footer">
        Already have an account? <Link to="/login">Sign in</Link>
      </div>
    </AuthShell>
  );
}
