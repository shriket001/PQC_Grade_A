/**
 * MfaSettingsModal — self-service TOTP enroll/disable (FR-009).
 *
 * No QR-code image is rendered: generating one client-side needs a new
 * dependency, and any external QR-image service would mean sending the TOTP
 * secret to a third party — a real leak of the second factor. The secret and
 * `otpauth://` URI are shown as text instead; every mainstream authenticator
 * app (Google/Microsoft/Authy, 1Password, etc.) supports typing/pasting a
 * base32 secret in by hand as well as scanning a code.
 */

import { useState } from "react";

import { Button } from "@/components/Button";
import { FormField } from "@/components/FormField";
import { ApiError } from "@/services/apiClient";
import { confirmMfa, disableMfa, enrollMfa } from "@/services/mfaService";
import { useAuthStore } from "@/store/authStore";
import { AUTH_ERROR_GUIDANCE, type AuthErrorCode } from "@/types/auth";

interface MfaSettingsModalProps {
  mfaEnabled: boolean;
  onClose: () => void;
}

type Step = "status" | "enroll" | "confirm" | "disable";

export function MfaSettingsModal({ mfaEnabled, onClose }: MfaSettingsModalProps): JSX.Element {
  const refreshMfaStatus = useAuthStore((s) => s.refreshMfaStatus);
  const [step, setStep] = useState<Step>(mfaEnabled ? "status" : "enroll");
  const [secret, setSecret] = useState<string | null>(null);
  const [otpauthUri, setOtpauthUri] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [disableWith, setDisableWith] = useState<"password" | "totp_code">("password");
  const [disableValue, setDisableValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [errorCode, setErrorCode] = useState<AuthErrorCode | null>(null);
  const [done, setDone] = useState<"enabled" | "disabled" | null>(null);

  async function handleStartEnroll(): Promise<void> {
    setBusy(true);
    setErrorCode(null);
    try {
      const res = await enrollMfa();
      setSecret(res.secret);
      setOtpauthUri(res.otpauth_uri);
      setStep("confirm");
    } catch (err) {
      setErrorCode(err instanceof ApiError ? err.errorCode : "unknown_error");
    } finally {
      setBusy(false);
    }
  }

  async function handleConfirm(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setErrorCode(null);
    try {
      await confirmMfa(totpCode);
      await refreshMfaStatus();
      setDone("enabled");
    } catch (err) {
      setErrorCode(err instanceof ApiError ? err.errorCode : "unknown_error");
    } finally {
      setBusy(false);
    }
  }

  async function handleDisable(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setErrorCode(null);
    try {
      await disableMfa(
        disableWith === "password" ? { password: disableValue } : { totp_code: disableValue },
      );
      await refreshMfaStatus();
      setDone("disabled");
    } catch (err) {
      setErrorCode(err instanceof ApiError ? err.errorCode : "unknown_error");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="form">
        <p>
          {done === "enabled"
            ? "Two-factor authentication is now enabled. You'll need a code from your authenticator app on your next sign-in."
            : "Two-factor authentication has been disabled."}
        </p>
        <Button type="button" onClick={onClose}>
          Done
        </Button>
      </div>
    );
  }

  return (
    <div className="form">
      {errorCode ? (
        <div className="alert" role="alert">
          <span className="alert__label">Error</span>
          <span>{AUTH_ERROR_GUIDANCE[errorCode]}</span>
        </div>
      ) : null}

      {step === "status" ? (
        <>
          <p>Two-factor authentication is currently enabled on your account.</p>
          <Button type="button" variant="ghost" onClick={() => setStep("disable")}>
            Turn off two-factor authentication
          </Button>
        </>
      ) : null}

      {step === "enroll" ? (
        <>
          <p>
            Add an authenticator app (Google Authenticator, Authy, 1Password, etc.) as a second
            sign-in factor.
          </p>
          <Button type="button" loading={busy} onClick={() => void handleStartEnroll()}>
            Start setup
          </Button>
        </>
      ) : null}

      {step === "confirm" && secret && otpauthUri ? (
        <form className="form" onSubmit={handleConfirm}>
          <p>Scan this in your authenticator app, or enter the secret manually:</p>
          <FormField label="Setup key" name="secret" mono readOnly value={secret} />
          <p className="field__hint">
            Or paste this URI directly if your app supports it: <code>{otpauthUri}</code>
          </p>
          <FormField
            label="Enter the 6-digit code from your app to confirm"
            name="totpCode"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            required
            mono
            placeholder="6-digit code"
            value={totpCode}
            invalid={errorCode === "invalid_mfa_code"}
            onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            autoFocus
          />
          <Button type="submit" loading={busy} disabled={totpCode.length !== 6}>
            Confirm and enable
          </Button>
        </form>
      ) : null}

      {step === "disable" ? (
        <form className="form" onSubmit={handleDisable}>
          <p>Confirm with your password or a current authenticator code to turn MFA off.</p>
          <div className="field">
            <label className="field__label">
              <input
                type="radio"
                name="disableWith"
                checked={disableWith === "password"}
                onChange={() => {
                  setDisableWith("password");
                  setDisableValue("");
                }}
              />{" "}
              Use my password
            </label>
            <label className="field__label">
              <input
                type="radio"
                name="disableWith"
                checked={disableWith === "totp_code"}
                onChange={() => {
                  setDisableWith("totp_code");
                  setDisableValue("");
                }}
              />{" "}
              Use an authenticator code
            </label>
          </div>
          <FormField
            label={disableWith === "password" ? "Password" : "6-digit code"}
            name="disableValue"
            type={disableWith === "password" ? "password" : "text"}
            inputMode={disableWith === "totp_code" ? "numeric" : undefined}
            mono={disableWith === "totp_code"}
            required
            value={disableValue}
            invalid={errorCode === "invalid_credentials" || errorCode === "invalid_mfa_code"}
            onChange={(e) =>
              setDisableValue(
                disableWith === "totp_code"
                  ? e.target.value.replace(/\D/g, "").slice(0, 6)
                  : e.target.value,
              )
            }
          />
          <Button type="submit" variant="danger" loading={busy} disabled={!disableValue}>
            Turn off two-factor authentication
          </Button>
        </form>
      ) : null}
    </div>
  );
}
