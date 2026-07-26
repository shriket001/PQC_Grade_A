/**
 * useRealtime — connects a `RealtimeClient` for the signed-in session and routes
 * inbound `message.new` events to the supplied handler. Reconnects with backoff
 * are handled inside the client; this hook only owns the lifecycle.
 */

import { useEffect, useRef } from "react";

import { RealtimeClient } from "@/services/realtimeClient";
import type { MessageNewData, ParticipantAddedData, ParticipantRemovedData } from "@/types/messaging";

export function useRealtime(
  onMessageNew: (data: MessageNewData) => void,
  onStatus?: (status: "disconnected" | "connecting" | "open") => void,
  onParticipantChange?: (data: ParticipantAddedData | ParticipantRemovedData) => void,
): void {
  const handlerRef = useRef(onMessageNew);
  handlerRef.current = onMessageNew;
  const statusRef = useRef(onStatus);
  statusRef.current = onStatus;
  const participantRef = useRef(onParticipantChange);
  participantRef.current = onParticipantChange;

  useEffect(() => {
    const client = new RealtimeClient();
    const offMsg = client.onMessageNew((data) => handlerRef.current(data));
    const offAdded = client.onParticipantAdded((data) => participantRef.current?.(data));
    const offRemoved = client.onParticipantRemoved((data) => participantRef.current?.(data));
    const offStatus = client.onStatus((s) => {
      // Map the client's "closed" to the store's "disconnected".
      const mapped = s === "closed" ? "disconnected" : s;
      statusRef.current?.(mapped);
    });
    client.connect();
    return () => {
      offMsg();
      offAdded();
      offRemoved();
      offStatus();
      client.disconnect();
    };
  }, []);
}