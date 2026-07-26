/**
 * DevicesModal — list active sessions/devices and revoke any of them
 * individually, with immediate effect (FR-006/US10).
 *
 * The CURRENT session never gets a "Sign out" button here — ending your own
 * live session is what the account panel's "Sign out" button already does;
 * this surface is specifically for logging out OTHER devices/logins.
 */

import { useEffect, useState } from "react";

import { Button } from "@/components/Button";
import { ApiError } from "@/services/apiClient";
import { listSessions, revokeSession } from "@/services/sessionService";
import { AUTH_ERROR_GUIDANCE, type AuthErrorCode, type SessionResponse } from "@/types/auth";

function formatSessionTime(iso: string): string {
  return new Date(iso).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function DevicesModal(): JSX.Element {
  const [sessions, setSessions] = useState<SessionResponse[] | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<AuthErrorCode | null>(null);

  useEffect(() => {
    void loadSessions();
  }, []);

  async function loadSessions(): Promise<void> {
    setErrorCode(null);
    try {
      const result = await listSessions();
      setSessions(result);
    } catch (err) {
      setErrorCode(err instanceof ApiError ? err.errorCode : "unknown_error");
    }
  }

  async function handleRevoke(sessionId: string): Promise<void> {
    setRevokingId(sessionId);
    setErrorCode(null);
    try {
      await revokeSession(sessionId);
      setSessions((prev) => (prev ? prev.filter((s) => s.session_id !== sessionId) : prev));
    } catch (err) {
      setErrorCode(err instanceof ApiError ? err.errorCode : "unknown_error");
    } finally {
      setRevokingId(null);
    }
  }

  return (
    <div className="form">
      {errorCode ? (
        <div className="alert" role="alert">
          <span className="alert__label">Error</span>
          <span>{AUTH_ERROR_GUIDANCE[errorCode]}</span>
        </div>
      ) : null}

      {sessions === null ? (
        <p>Loading your devices…</p>
      ) : sessions.length === 0 ? (
        <p>No active sessions.</p>
      ) : (
        <ul className="devices-list">
          {sessions.map((s) => (
            <li key={s.session_id} className="devices-list__row">
              <div>
                <strong>{s.device_context ?? "Unknown device"}</strong>
                <br />
                <span className="mono" style={{ color: "var(--ink-faint)", fontSize: "0.78rem" }}>
                  Signed in {formatSessionTime(s.created_at)}
                </span>
              </div>
              {s.current ? (
                <span className="devices-list__badge">This device</span>
              ) : (
                <Button
                  type="button"
                  variant="ghost"
                  loading={revokingId === s.session_id}
                  onClick={() => void handleRevoke(s.session_id)}
                >
                  Sign out
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
