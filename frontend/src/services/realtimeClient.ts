/**
 * Realtime WebSocket client (US2, T062) — thin wrapper over the `/api/v1/ws`
 * contract (contracts/websocket-events.md).
 *
 * Authenticates at upgrade time via the access_token query param (the apiClient
 * builds the URL). Dispatches inbound `message.new` events to subscribers; sends
 * outbound `message.send` events. Reconnects with bounded backoff on unexpected
 * close. This client carries only ciphertext + envelope — never plaintext or
 * private keys (FR-051).
 */

import { getAccessToken, openRealtimeConnection } from "@/services/apiClient";
import type {
  MessageEnvelope,
  MessageNewData,
  ParticipantAddedData,
  ParticipantRemovedData,
  WsErrorData,
  WsEvent,
} from "@/types/messaging";

type MessageNewHandler = (data: MessageNewData) => void;
type ParticipantAddedHandler = (data: ParticipantAddedData) => void;
type ParticipantRemovedHandler = (data: ParticipantRemovedData) => void;
type ErrorHandler = (data: WsErrorData) => void;
type StatusHandler = (status: "connecting" | "open" | "closed") => void;

const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 8000;

export interface RealtimeEvent {
  type: string;
  data: unknown;
}

export class RealtimeClient {
  private socket: WebSocket | null = null;
  private messageNewHandlers = new Set<MessageNewHandler>();
  private participantAddedHandlers = new Set<ParticipantAddedHandler>();
  private participantRemovedHandlers = new Set<ParticipantRemovedHandler>();
  private errorHandlers = new Set<ErrorHandler>();
  private statusHandlers = new Set<StatusHandler>();
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  /**
   * Pending deferred-connect timer. The actual `new WebSocket()` is scheduled on
   * a macrotask so a rapid `connect()`→`disconnect()` (React StrictMode's
   * mount→unmount→remount in dev) can cancel it before any socket is created —
   * otherwise the unmount closes a still-CONNECTING socket and the browser logs
   * "WebSocket is closed before the connection is established."
   */
  private connectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionallyClosed = false;

  onMessageNew(handler: MessageNewHandler): () => void {
    this.messageNewHandlers.add(handler);
    return () => this.messageNewHandlers.delete(handler);
  }

  /** US3 (T068): a group's membership changed — treat as a group-key-epoch
   * rotation trigger (websocket-events.md). */
  onParticipantAdded(handler: ParticipantAddedHandler): () => void {
    this.participantAddedHandlers.add(handler);
    return () => this.participantAddedHandlers.delete(handler);
  }

  onParticipantRemoved(handler: ParticipantRemovedHandler): () => void {
    this.participantRemovedHandlers.add(handler);
    return () => this.participantRemovedHandlers.delete(handler);
  }

  onError(handler: ErrorHandler): () => void {
    this.errorHandlers.add(handler);
    return () => this.errorHandlers.delete(handler);
  }

  onStatus(handler: StatusHandler): () => void {
    this.statusHandlers.add(handler);
    return () => this.statusHandlers.delete(handler);
  }

  private emitStatus(status: "connecting" | "open" | "closed"): void {
    for (const h of this.statusHandlers) h(status);
  }

  connect(): void {
    if (!getAccessToken()) {
      // Nothing to connect with — callers should ensure a session first.
      return;
    }
    this.intentionallyClosed = false;
    this.emitStatus("connecting");
    // Defer the socket creation so a connect→disconnect that lands within the
    // same task (StrictMode dev double-invoke) cancels before opening — avoids
    // closing a still-CONNECTING socket and the console error that follows.
    if (this.connectTimer) clearTimeout(this.connectTimer);
    this.connectTimer = setTimeout(() => {
      this.connectTimer = null;
      this.open();
    }, 0);
  }

  private open(): void {
    const socket = openRealtimeConnection();
    this.socket = socket;

    socket.addEventListener("open", () => {
      this.reconnectAttempts = 0;
      this.emitStatus("open");
    });

    socket.addEventListener("message", (event) => {
      this.handleRaw(event.data);
    });

    socket.addEventListener("close", () => {
      this.socket = null;
      this.emitStatus("closed");
      if (!this.intentionallyClosed) {
        this.scheduleReconnect();
      }
    });

    socket.addEventListener("error", () => {
      // The close handler drives reconnection; errors surface as a close after.
    });
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    const delay = Math.min(RECONNECT_BASE_MS * 2 ** this.reconnectAttempts, RECONNECT_MAX_MS);
    this.reconnectAttempts += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private handleRaw(raw: unknown): void {
    let parsed: WsEvent;
    try {
      parsed = JSON.parse(typeof raw === "string" ? raw : String(raw)) as WsEvent;
    } catch {
      return;
    }
    if (parsed.type === "message.new") {
      for (const h of this.messageNewHandlers) h(parsed.data as unknown as MessageNewData);
    } else if (parsed.type === "conversation.participant_added") {
      for (const h of this.participantAddedHandlers) {
        h(parsed.data as unknown as ParticipantAddedData);
      }
    } else if (parsed.type === "conversation.participant_removed") {
      for (const h of this.participantRemovedHandlers) {
        h(parsed.data as unknown as ParticipantRemovedData);
      }
    } else if (parsed.type === "error") {
      for (const h of this.errorHandlers) h(parsed.data as unknown as WsErrorData);
    }
  }

  send(input: {
    conversation_id: string;
    ciphertext: string;
    envelope: MessageEnvelope;
    sender_identity_key_id: string;
  }): void {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error("realtime socket not open");
    }
    const event: WsEvent<"message.send", typeof input> = { type: "message.send", data: input };
    this.socket.send(JSON.stringify(event));
  }

  get status(): "connecting" | "open" | "closed" {
    if (this.connectTimer) return "connecting";
    if (!this.socket) return "closed";
    if (this.socket.readyState === WebSocket.OPEN) return "open";
    if (this.socket.readyState === WebSocket.CONNECTING) return "connecting";
    return "closed";
  }

  disconnect(): void {
    this.intentionallyClosed = true;
    if (this.connectTimer) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.emitStatus("closed");
  }
}