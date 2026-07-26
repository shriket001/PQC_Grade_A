/**
 * Messaging store (zustand) — the UI-facing state for the E2EE 1:1 surface (US2).
 *
 * Owns: the conversation list, the active conversation, the per-conversation
 * decrypted message log, the local identity readiness flag, the realtime
 * connection status, and a peer-username cache so the rail + thread show real
 * handles instead of truncated ids. Crypto is delegated to `conversationCrypto`
 * + `vault`; the store never holds plaintext keys in state longer than needed
 * and never sends plaintext or private keys to the API (FR-051).
 *
 * Starting a conversation is username-driven (FR-052/FR-053): the typed handle
 * is resolved to a user id through `/users/search`, then the direct conversation
 * is created with that resolved id — the enterprise-standard flow, no out-of-band
 * session/UUID copying.
 */

import { create } from "zustand";

import { base64ToBytes, bytesToBase64 } from "@/crypto/bytes";
import {
  conversationKeyStore,
  MessageAuthenticityError,
  openIncoming,
  openMessage,
  prepareOutgoing,
  type ConversationKeyMaterial,
  type PeerPublicKeys,
} from "@/crypto/conversationCrypto";
import { unwrapConversationKey, wrapConversationKey } from "@/crypto/conversationKeyBackup";
import {
  openFile,
  packFilePlaintext,
  sealFile,
  unpackFilePlaintext,
  validateFileForUpload,
} from "@/crypto/fileCrypto";
import {
  acceptKeyDistribution,
  buildKeyDistributionExtra,
  createAndWrapNewEpoch,
  groupKeyStore,
  openGroupMessage,
  parseKeyDistributionExtra,
  sealGroupMessage,
} from "@/crypto/providers/groupKeyManager";
import { IdentityLockedError, unlockIdentity, type LocalIdentity } from "@/crypto/vault";
import { downloadFile as apiDownloadFile, uploadFile as apiUploadFile } from "@/services/fileService";
import {
  addParticipant as apiAddParticipant,
  createConversation as apiCreateConversation,
  deleteConversation as apiDeleteConversation,
  fetchConversationKeyBackup,
  fetchMyWrappedIdentity,
  listConversations as apiListConversations,
  listIdentityKeys,
  listMessages as apiListMessages,
  publishIdentityKey,
  putConversationKeyBackup,
  removeParticipant as apiRemoveParticipant,
  sendMessage as apiSendMessage,
} from "@/services/messagingService";
import { getUserSummary, searchUsers } from "@/services/userService";
import { useAuthStore } from "@/store/authStore";
import type {
  ConversationResponse,
  MessageEnvelope,
  MessageNewData,
  MessageResponse,
} from "@/types/messaging";

interface MessagingState {
  identity: LocalIdentity | null;
  identityReady: boolean;
  /**
   * True when the bootstrap could not load an identity without a password (no
   * cached unwrapped identity in this browser). The Conversations page shows an
   * "unlock messages" prompt; `unlockWithPassword` completes the flow.
   */
  identityLocked: boolean;
  /**
   * True when `identityLocked` is showing because NO wrapped identity exists
   * on the server yet — i.e. this is the very first time this account is
   * establishing its E2EE identity (always true for a brand-new OAuth/Google
   * account, which has no password of its own to have unlocked with already).
   * The unlock prompt uses this to say "choose a password" rather than
   * "enter your password", since there is nothing pre-existing to recall.
   * False (the default/safe assumption) whenever a wrapped record IS found,
   * or its existence couldn't be determined.
   */
  identityFirstTimeSetup: boolean;
  conversations: ConversationResponse[];
  activeConversationId: string | null;
  /** Oldest-first message log per conversation (decrypted lazily on open). */
  messagesByConversation: Record<string, MessageResponse[]>;
  /** Resolved username per peer user id, for rail + thread labels. */
  peerUsernameById: Record<string, string>;
  /**
   * FR-058: client-decrypted latest-message preview per conversation, for the
   * rail. The server holds only `last_message_at` (a timestamp); the preview
   * text is decrypted in the browser (FR-051) and lives only in memory here —
   * never persisted, never sent to the backend.
   */
  lastMessagePreviewByConversation: Record<string, string>;
  /**
   * FR-028 (UI): per group conversation, how many messages were hidden from the
   * active user because they were sent before the user joined (and so sealed
   * under an earlier epoch key the user was never given — they can't be
   * decrypted, by design). The thread shows a single "you were added" notice
   * instead of one decrypt-error bubble per hidden message.
   */
  hiddenPreJoinCountByConversation: Record<string, number>;
  /** Per group conversation, how many displayed group messages were hidden
   * because this device holds no epoch key for them — e.g. after an identity
   * rotation reset the keypair the old epoch keys were wrapped for (the
   * "no group key for epoch N" case). Like the pre-join count, these can't
   * be decrypted by design, so they're dropped from the log and summarized
   * by a single thread notice instead of one "Couldn't decrypt …" bubble
   * per row. Pre-join messages are NOT counted here (they have their own
   * notice via `hiddenPreJoinCountByConversation`). */
  hiddenNoKeyCountByConversation: Record<string, number>;
  realtimeStatus: "disconnected" | "connecting" | "open";
  error: string | null;
  sending: boolean;
  /** Bumped whenever `decryptedFileCache`/`fileLoadErrors` mutate, so
   * components reading `getDecryptedFile`/`getFileLoadError` re-render (those
   * caches live outside zustand state, mirroring `decryptedCache`). */
  fileCacheVersion: number;

  bootstrap: () => Promise<void>;
  /** Re-run the identity bootstrap with an entered password (unlock prompt). */
  unlockWithPassword: (password: string) => Promise<void>;
  refreshConversations: () => Promise<void>;
  selectConversation: (conversationId: string) => Promise<void>;
  /** Resolve a username through the directory and start a direct conversation. */
  startConversation: (username: string) => Promise<string | null>;
  /**
   * Create a group conversation (US3, FR-024): resolves each username, creates
   * the group, then generates + distributes the first group-key epoch to every
   * other member (an opaque key-distribution message through the same
   * ciphertext+envelope pipeline as regular content — see `groupKeyManager.ts`).
   */
  startGroup: (name: string, usernames: string[]) => Promise<string | null>;
  /** Add a member to a group (group_admin only) and issue a fresh key epoch
   * that includes them (FR-024). */
  addGroupMember: (conversationId: string, username: string) => Promise<boolean>;
  /** Remove a member from a group, or leave it yourself, and issue a fresh key
   * epoch that excludes the removed member (FR-024/FR-028). */
  removeGroupMember: (conversationId: string, userId: string) => Promise<boolean>;
  /** Manually issue a fresh group-key epoch addressed to every current
   * member's ACTIVE identity key — the recovery path for a member whose
   * device holds no epoch key (e.g. after an identity rotation reset the
   * keypair the old epoch keys were wrapped for). Bumps the epoch to one
   * strictly greater than any seen in the group's message history, so it
   * never collides with / overwrites an existing epoch other members may
   * still hold. */
  rekeyGroup: (conversationId: string) => Promise<boolean>;
  /**
   * Leave a conversation (FR-055 per-user soft delete): the server stamps the
   * caller's `left_at` (the peer keeps their copy + history), then this drops
   * the conversation from the local rail + clears its key/log.
   */
  deleteConversation: (conversationId: string) => Promise<boolean>;
  sendOutgoing: (plaintext: string) => Promise<void>;
  /** Encrypt + upload a file/image share (US4) into the active conversation.
   * Requires the conversation key (direct) or a current group epoch to
   * already be established — send a text message first in a brand-new
   * conversation/group before sharing a file. */
  sendFile: (file: File) => Promise<void>;
  /** Lazily download + decrypt a file/image share's ciphertext (not fetched
   * up front with the rest of the message log, to avoid pulling every shared
   * file's bytes just to render a thread). Populates the in-memory
   * `decryptedFileCache`/`fileLoadErrors` the UI reads via
   * `getDecryptedFile`/`getFileLoadError`. */
  loadFile: (conversationId: string, message: MessageResponse) => Promise<void>;
  ingestRealtimeMessage: (data: MessageNewData) => Promise<void>;
  setRealtimeStatus: (status: "disconnected" | "connecting" | "open") => void;
  /** US3 (T068): react to a `conversation.participant_added/removed` WS event
   * by refreshing membership + (if open) re-syncing the conversation's
   * messages so a new group-key epoch gets picked up. */
  onGroupMembershipChanged: (conversationId: string) => Promise<void>;
  clearError: () => void;
}

/** Resolve a user's active public key pair from the directory (highest version). */
async function fetchPeerPublicKeys(userId: string): Promise<PeerPublicKeys> {
  const keys = await listIdentityKeys(userId);
  if (!keys.length) {
    throw new Error(`peer has no published identity keys`);
  }
  // The directory returns active keys, highest key_version first.
  const active = keys[0];
  return {
    signingPublicKey: base64ToBytes(active.public_signing_key),
    kemPublicKey: base64ToBytes(active.public_kem_key),
  };
}

/**
 * Resolve the EXACT public signing key for a given `(userId, keyId)` — the key
 * that signed a specific message — with an in-memory cache so a conversation
 * log with many messages signed by the same key does not re-fetch per message.
 * Throws if that key id is not published (e.g. the sender rotated and the old
 * version is no longer listed).
 */
const senderSigningKeyCache = new Map<string, Uint8Array>();
async function fetchSenderSigningKey(userId: string, keyId: string): Promise<Uint8Array> {
  const cached = senderSigningKeyCache.get(keyId);
  if (cached) return cached;
  const keys = await listIdentityKeys(userId);
  const hit = keys.find((k) => k.id === keyId);
  if (!hit) {
    throw new Error("sender identity key not found (it may have been rotated)");
  }
  const pub = base64ToBytes(hit.public_signing_key);
  senderSigningKeyCache.set(keyId, pub);
  return pub;
}

/** Resolve a user's active identity-key id + KEM public key (for wrapping a
 * group epoch key to them). Throws if they have no published identity keys
 * (they've registered but never signed in / unlocked messages, which is what
 * publishes identity keys — see `bootstrap()`). */
async function fetchPeerIdentityKey(
  userId: string,
  username: string,
): Promise<{ keyId: string; kemPublicKey: Uint8Array }> {
  const keys = await listIdentityKeys(userId);
  if (!keys.length) {
    throw new Error(
      `@${username} hasn't set up encrypted messaging yet (they need to sign in at least once before they can be added to a group).`,
    );
  }
  const active = keys[0];
  return { keyId: active.id, kemPublicKey: base64ToBytes(active.public_kem_key) };
}

/**
 * Generate a new group-key epoch, wrap it for every given recipient, store it
 * locally, and send it as an opaque key-distribution message (the SAME
 * ciphertext+envelope pipeline as regular content — no new backend surface).
 * The trivial marker plaintext ("🔑") is sealed under the new key purely so
 * the message is a well-formed signed/encrypted record; recipients never
 * display it (`openIncomingForConversation` returns null for it).
 */
async function distributeNewGroupEpoch(
  conversationId: string,
  identity: LocalIdentity,
  recipients: Array<{ identityKeyId: string; kemPublicKey: Uint8Array }>,
  baseEpoch?: number,
): Promise<void> {
  // `baseEpoch` lets a caller (the manual `rekeyGroup` recovery path) pin the
  // previous epoch to the group's ACTUAL current epoch even when this device
  // holds no prior key — so the new epoch is strictly greater than any existing
  // one and never collides with / overwrites an epoch other members may still
  // hold. When omitted, fall back to this device's stored current epoch.
  const previousEpoch = baseEpoch ?? groupKeyStore.getCurrentEpoch(conversationId) ?? 0;
  const { epoch, key, keyWraps } = await createAndWrapNewEpoch(previousEpoch, recipients);
  groupKeyStore.setKey(conversationId, epoch, key);

  const marker = new TextEncoder().encode("🔑");
  const sealed = await sealGroupMessage(
    key,
    marker,
    identity.signingPrivateKey,
    conversationId,
    identity.keyId,
    epoch,
  );
  const envelope: MessageEnvelope = {
    alg: "aes-256-gcm",
    nonce: bytesToBase64(sealed.nonce),
    version: 1,
    sig: bytesToBase64(sealed.signature),
    ...buildKeyDistributionExtra({ epoch, keyWraps }),
  };
  await apiSendMessage(conversationId, {
    ciphertext: bytesToBase64(sealed.ciphertext),
    envelope,
    sender_identity_key_id: identity.keyId,
  });
}

/** True when `message` is a file/image share (US4) rather than a text
 * message — it carries an empty `ciphertext` on the Message row itself (the
 * real encrypted bytes live in a separate FileAttachment, fetched lazily via
 * `loadFile` when the bubble is opened) plus `file_attachment_id` in the
 * envelope. */
export function isFileMessage(message: MessageResponse): boolean {
  return message.envelope.kind === "file";
}

/**
 * Decrypt (or, for a key-distribution message, absorb) one incoming message
 * for `conv`. Returns the plaintext, or null when the message was a group
 * key-distribution record (nothing to display), a file/image share (rendered
 * via `loadFile` instead of the text-decrypt path), or the local user had no
 * wrap in it (not yet a member / already removed for that epoch — silently
 * skipped, not an error). Throws on a genuine decryption/verification failure.
 */
async function openIncomingForConversation(
  conv: ConversationResponse,
  message: MessageResponse,
  identity: LocalIdentity,
  fetchSigningKey: (userId: string, keyId: string) => Promise<Uint8Array>,
): Promise<string | null> {
  if (isFileMessage(message)) {
    return null; // rendered as a file bubble, decrypted lazily via loadFile
  }
  if (conv.type === "group") {
    const dist = parseKeyDistributionExtra(message.envelope);
    if (dist) {
      const key = await acceptKeyDistribution(dist, identity.keyId, identity.kemPrivateKey);
      if (key) groupKeyStore.setKey(conv.id, dist.epoch, key);
      return null; // key material, never displayed as content
    }
    const epoch = message.envelope.epoch;
    if (typeof epoch !== "number") {
      throw new Error("group message missing epoch");
    }
    const key = groupKeyStore.getKey(conv.id, epoch);
    if (!key) {
      throw new Error(`no group key for epoch ${epoch} — you may have joined after this message`);
    }
    const senderSigningPublicKey = await fetchSigningKey(
      message.sender_id,
      message.sender_identity_key_id,
    );
    const plaintext = await openGroupMessage(
      key,
      base64ToBytes(message.ciphertext),
      base64ToBytes(String(message.envelope.nonce)),
      base64ToBytes(String(message.envelope.sig)),
      senderSigningPublicKey,
      conv.id,
      message.sender_identity_key_id,
      epoch,
    );
    return new TextDecoder().decode(plaintext);
  }

  const existingKey = await resolveConversationKey(conv.id, identity);

  // A message I sent myself (re-decrypted from history — e.g. after a
  // refresh wipes the in-memory plaintext cache) must NEVER go through
  // `openIncoming`'s KEM-decapsulation path, even though it carries
  // `envelope.kem` when it was the keying message: that ciphertext was
  // encapsulated against the PEER's public key, and only their private key
  // can decapsulate it. My own client decapsulating it against MY OWN KEM
  // private key derives garbage, failing the AEAD tag ("invalid tag") on my
  // own first message every time. I already hold the exact key I sealed it
  // with (established at send time, or recovered via the key backup) — reuse
  // that directly instead.
  const selfUserId = useAuthStore.getState().session?.userId ?? "";
  if (message.sender_id === selfUserId) {
    if (!existingKey) {
      throw new MessageAuthenticityError("missing local key for your own message");
    }
    const signatureB64 = message.envelope.sig;
    if (typeof signatureB64 !== "string") {
      throw new MessageAuthenticityError("missing signature");
    }
    const plaintext = await openMessage(
      existingKey.messageKey,
      base64ToBytes(message.ciphertext),
      base64ToBytes(String(message.envelope.nonce)),
      base64ToBytes(signatureB64),
      identity.signingPublicKey,
      conv.id,
      message.sender_identity_key_id,
    );
    return new TextDecoder().decode(plaintext);
  }

  const { plaintext, key } = await openIncoming(message, identity, existingKey, fetchSigningKey);
  const isNewKey = !existingKey || key.messageKey !== existingKey.messageKey;
  conversationKeyStore.set(conv.id, key);
  if (isNewKey) void backupConversationKey(conv.id, identity, key);
  return new TextDecoder().decode(plaintext);
}

/**
 * Resolve a 1:1 conversation's message key: the local cache first, else the
 * server-side password-wrapped backup (see `conversationKeyBackup.ts`) — this
 * is what recovers an INITIATOR's key after a browser-storage clear, since
 * (unlike the recipient side) it can never be re-derived from message history
 * alone. Best-effort: any backup-fetch/unwrap failure is swallowed and null is
 * returned, falling through to the normal "no key yet" handling.
 */
async function resolveConversationKey(
  conversationId: string,
  identity: LocalIdentity,
): Promise<ConversationKeyMaterial | null> {
  const local = conversationKeyStore.get(conversationId);
  if (local) return local;
  if (!identity.wrapKey) return null;
  try {
    const backup = await fetchConversationKeyBackup(conversationId);
    if (!backup) return null;
    const messageKey = await unwrapConversationKey(identity.wrapKey, backup, conversationId);
    // The backup carries only the symmetric key, not the peer's signing public
    // key — that's re-resolved per-message by key id anyway (see
    // `fetchSenderSigningKey`), so a placeholder here is never actually used
    // for verification; `openIncoming`/`openMessage` always take the fresh one.
    const key: ConversationKeyMaterial = { messageKey, peerSigningPublicKey: new Uint8Array(0) };
    conversationKeyStore.set(conversationId, key);
    return key;
  } catch {
    return null;
  }
}

/**
 * Best-effort push of a newly-established 1:1 conversation key to the
 * server-side backup, wrapped under the session's password-derived key. Never
 * throws — a failed backup only risks losing THIS key on a future storage
 * clear, it must not block sending/receiving the current message.
 */
async function backupConversationKey(
  conversationId: string,
  identity: LocalIdentity,
  key: ConversationKeyMaterial,
): Promise<void> {
  if (!identity.wrapKey || !identity.wrapKdfSalt || !identity.wrapKdfParams) return;
  try {
    const input = await wrapConversationKey(
      identity.wrapKey,
      identity.wrapKdfSalt,
      identity.wrapKdfParams,
      key.messageKey,
      conversationId,
    );
    await putConversationKeyBackup(conversationId, input);
  } catch {
    // Best-effort — see docstring.
  }
}

/**
 * Fetch a conversation's ENTIRE message history (oldest-first), walking
 * `next_cursor` back through every older page instead of stopping at the
 * newest 50/200. Message history is paginated server-side, but the
 * conversation's very first message carries the ML-KEM-768 keying ciphertext
 * (`envelope.kem`) that a client with no cached key needs to derive the
 * session key at all — stopping at the first page silently drops that
 * message once a conversation grows past one page, producing "missing KEM
 * ciphertext on keying message" on an otherwise-healthy conversation.
 */
async function fetchAllMessages(conversationId: string): Promise<MessageResponse[]> {
  const pages: MessageResponse[][] = [];
  let cursor: string | null = null;
  do {
    const page = await apiListMessages(conversationId, cursor, 200);
    pages.push(page.messages);
    cursor = page.next_cursor;
  } while (cursor);
  // Each page is oldest-first internally, but later fetches are for OLDER
  // pages, so reverse the page order before flattening.
  return pages.reverse().flat();
}

function otherParticipantUserId(conv: ConversationResponse, selfUserId: string): string {
  const other = conv.participants.find((p) => p.user_id !== selfUserId);
  if (!other) {
    // Fallback for a conversation where self is the only listed participant
    // (shouldn't happen for direct) — use created_by's counterpart defensively.
    return conv.created_by === selfUserId
      ? conv.participants[0]?.user_id ?? selfUserId
      : conv.created_by;
  }
  return other.user_id;
}

/**
 * Resolve peer usernames for the given conversations (best-effort, in parallel)
 * so the rail + thread can render handles instead of truncated ids. Failures are
 * swallowed — the UI falls back to the id prefix.
 */
async function resolvePeerUsernames(
  conversations: ConversationResponse[],
  set: (
    partial: Partial<MessagingState> | ((s: MessagingState) => Partial<MessagingState>),
  ) => void,
  get: () => MessagingState,
): Promise<void> {
  const selfUserId = useAuthStore.getState().session?.userId ?? "";
  const cache = get().peerUsernameById;
  const toResolve = new Set<string>();
  for (const c of conversations) {
    const peerId = otherParticipantUserId(c, selfUserId);
    if (peerId && !cache[peerId]) toResolve.add(peerId);
  }
  await Promise.all(
    [...toResolve].map(async (peerId) => {
      try {
        const summary = await getUserSummary(peerId);
        set((s) => ({ peerUsernameById: { ...s.peerUsernameById, [peerId]: summary.username } }));
      } catch {
        // Non-blocking; truncated-id fallback stays in place.
      }
    }),
  );
}

/**
 * FR-058: order conversations newest-first by `last_message_at` (nulls last),
 * then by `created_at` desc — the same ordering the server applies in
 * `list_for_user`. Used after local mutations (send, realtime ingest, start) so
 * the rail matches what a server refresh would show without a round-trip.
 */
function sortConversations(list: ConversationResponse[]): ConversationResponse[] {
  return [...list].sort((a, b) => {
    const am = a.last_message_at ?? null;
    const bm = b.last_message_at ?? null;
    if (am && bm) return bm.localeCompare(am);
    if (am && !bm) return -1;
    if (!am && bm) return 1;
    return b.created_at.localeCompare(a.created_at);
  });
}

/** True when `message` is a group key-distribution record (US3) rather than
 * displayable chat content — it never carries user-facing text. */
function isKeyDistributionMessage(conv: ConversationResponse, message: MessageResponse): boolean {
  return conv.type === "group" && parseKeyDistributionExtra(message.envelope) !== null;
}

/**
 * FR-058: best-effort, parallel seeding of the rail preview for each
 * conversation. Fetches the latest message (`?limit=1`) per conversation and
 * decrypts it in the browser (FR-051) — the server provides only the
 * `last_message_at` timestamp, never a readable preview. Conversations whose
 * latest message cannot be decrypted here (e.g. a new browser with no cached
 * conversation key, a non-keying latest message, or the latest record being a
 * group key-distribution message) simply get no preview until the thread is
 * opened; failures are swallowed.
 */
async function seedPreviews(
  conversations: ConversationResponse[],
  identity: LocalIdentity,
  set: (
    partial: Partial<MessagingState> | ((s: MessagingState) => Partial<MessagingState>),
  ) => void,
): Promise<void> {
  await Promise.all(
    conversations.map(async (c) => {
      try {
        const page = await apiListMessages(c.id, null, 1);
        const latest = page.messages[page.messages.length - 1];
        if (!latest) return; // no messages yet — no preview
        const text = await openIncomingForConversation(c, latest, identity, fetchSenderSigningKey);
        if (text === null) return; // key-distribution record — no preview text
        set((s) => ({
          lastMessagePreviewByConversation: {
            ...s.lastMessagePreviewByConversation,
            [c.id]: text,
          },
        }));
      } catch {
        // Best-effort: the rail falls back to the peer username + time only.
      }
    }),
  );
}

export const useMessagingStore = create<MessagingState>((set, get) => ({
  // Loaded per-user in `bootstrap()` (the userId is unavailable at store
  // creation time); null until then.
  identity: null,
  identityReady: false,
  identityLocked: false,
  identityFirstTimeSetup: false,
  conversations: [],
  activeConversationId: null,
  messagesByConversation: {},
  peerUsernameById: {},
  lastMessagePreviewByConversation: {},
  hiddenPreJoinCountByConversation: {},
  hiddenNoKeyCountByConversation: {},
  realtimeStatus: "disconnected",
  error: null,
  sending: false,
  fileCacheVersion: 0,

  async bootstrap() {
    // Load the signed-in user's profile (username/email) from /users/me so the
    // shell shows the real handle instead of the JWT-seeded placeholder.
    void useAuthStore.getState().loadProfile();
    const userId = useAuthStore.getState().session?.userId;
    if (!userId) {
      set({ error: "not signed in" });
      return;
    }
    // FR-054: the identity is recovered (or generated+wrapped) from the
    // password. The transient password is captured at login and held in memory
    // by the auth store solely for this handoff; consume + clear it here.
    const auth = useAuthStore.getState();
    const password = auth.pendingUnlockPassword;
    try {
      const identity = await unlockIdentity(
        userId,
        password,
        { fetchWrapped: fetchMyWrappedIdentity, publishWrapped: publishIdentityKey },
      );
      useAuthStore.getState().setPendingUnlockPassword(null);
      set({ identity, identityReady: true, identityLocked: false });
      const conversations = await apiListConversations();
      set({ conversations });
      void resolvePeerUsernames(conversations, set, get);
      // FR-058: seed the rail previews (client-decrypted latest message per
      // conversation) so the list is useful immediately on login/refresh.
      void seedPreviews(conversations, identity, set);
    } catch (err) {
      if (err instanceof IdentityLockedError) {
        // No cached identity + no password on hand (e.g. a page refresh after
        // storage clear while the access token still persists, or an
        // OAuth/Google login — which never has a `pendingUnlockPassword` at
        // all, since there was no password step). Determine which prompt copy
        // fits: has this account ever wrapped+published an identity before?
        let firstTimeSetup = false;
        try {
          const existing = await fetchMyWrappedIdentity();
          firstTimeSetup = existing === null || !existing.wrapped_signing_private_key;
        } catch {
          // Best-effort — if we can't tell, default to the safer "returning
          // user" copy (identityFirstTimeSetup stays false) rather than
          // risk telling someone with a real existing password to pick a
          // fresh one.
        }
        set({
          identityLocked: true,
          identityReady: false,
          identityFirstTimeSetup: firstTimeSetup,
          error: null,
        });
        return;
      }
      set({ error: err instanceof Error ? err.message : "failed to initialize messaging" });
    }
  },

  async unlockWithPassword(password) {
    const userId = useAuthStore.getState().session?.userId;
    if (!userId) {
      set({ error: "not signed in" });
      return;
    }
    set({ error: null });
    try {
      const identity = await unlockIdentity(
        userId,
        password,
        { fetchWrapped: fetchMyWrappedIdentity, publishWrapped: publishIdentityKey },
      );
      // Stash + clear exactly as in bootstrap so a future refresh reuses the
      // cache (the password is not retained beyond this handoff).
      useAuthStore.getState().setPendingUnlockPassword(null);
      set({ identity, identityReady: true, identityLocked: false });
      const conversations = await apiListConversations();
      set({ conversations });
      void resolvePeerUsernames(conversations, set, get);
      void seedPreviews(conversations, identity, set);
    } catch (err) {
      // A wrong password makes the Poly1305 tag fail to verify on unwrap.
      if (err instanceof IdentityLockedError) {
        set({ error: "Password is required to unlock your messages." });
        return;
      }
      set({
        identityLocked: true,
        error: err instanceof Error ? err.message : "wrong password — could not unlock messages",
      });
    }
  },

  async refreshConversations() {
    try {
      const conversations = await apiListConversations();
      set({ conversations });
      void resolvePeerUsernames(conversations, set, get);
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "failed to load conversations" });
    }
  },

  async selectConversation(conversationId) {
    set({ activeConversationId: conversationId });
    try {
      const messages = await fetchAllMessages(conversationId);
      const conv = get().conversations.find((c) => c.id === conversationId);
      // The backend returns oldest-first; group key-distribution records are
      // never shown as chat bubbles (they carry no user-facing text). For a
      // group, also hide any message sent before the active user joined
      // (FR-028): those were sealed under an earlier epoch key the user was
      // never given and genuinely can't be decrypted — rendering one
      // "Couldn't decrypt … you may have joined after" bubble per hidden
      // message is wrong, so they're dropped from the displayed log and counted
      // for a single "you were added" notice instead.
      const selfUserId = useAuthStore.getState().session?.userId ?? "";
      let hiddenPreJoin = 0;
      const displayMessages = conv
        ? messages.filter((m) => {
            if (isKeyDistributionMessage(conv, m)) return false;
            if (conv.type === "group") {
              const me = conv.participants.find((p) => p.user_id === selfUserId);
              if (me) {
                const joinedMs = Date.parse(me.joined_at);
                const sentMs = Date.parse(m.sent_at);
                if (!Number.isNaN(joinedMs) && !Number.isNaN(sentMs) && sentMs < joinedMs) {
                  hiddenPreJoin += 1;
                  return false;
                }
              }
            }
            return true;
          })
        : messages;
      set((state) => ({
        messagesByConversation: {
          ...state.messagesByConversation,
          [conversationId]: displayMessages,
        },
        hiddenPreJoinCountByConversation: {
          ...state.hiddenPreJoinCountByConversation,
          [conversationId]: hiddenPreJoin,
        },
      }));
      const identity = get().identity;
      if (identity && conv) {
        // Decrypt the freshly loaded log in-memory (plaintext never persists).
        // The FULL list (including key-distribution records) is processed so
        // every epoch key this device is entitled to gets absorbed. Pre-join
        // group messages are skipped here too (already hidden from display),
        // and group messages whose epoch key this device doesn't hold are
        // skipped + counted for a single notice rather than rendered as
        // per-row "Couldn't decrypt … no group key for epoch N" bubbles.
        const noKeyCount = await decryptConversationLog(conv, messages, identity);
        set((s) => ({
          hiddenNoKeyCountByConversation: {
            ...s.hiddenNoKeyCountByConversation,
            [conversationId]: noKeyCount,
          },
        }));
        // FR-058: seed the rail preview from the latest DISPLAYABLE decrypted
        // message (the page is oldest-first, so the newest is last).
        const latest = displayMessages[displayMessages.length - 1];
        if (latest) {
          const previewText = decryptedCache.get(latest.id);
          if (previewText) {
            set((s) => ({
              lastMessagePreviewByConversation: {
                ...s.lastMessagePreviewByConversation,
                [conversationId]: previewText,
              },
            }));
          }
        }
      }
      // Make sure the active peer's handle is resolved for the thread head.
      if (conv) void resolvePeerUsernames([conv], set, get);
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "failed to load messages" });
    }
  },

  async startConversation(username) {
    const handle = username.trim();
    if (!handle) {
      set({ error: "Enter a username to start a conversation." });
      return null;
    }
    try {
      // 1. Resolve the typed handle to a user id through the directory — the
      //    "verify the user exists" step. Search is exact + case-insensitive.
      const matches = await searchUsers(handle);
      const hit = matches.find((m) => m.username.toLowerCase() === handle.toLowerCase());
      if (!hit) {
        set({ error: `No user found with the username “${handle}”.` });
        return null;
      }
      // 2. Create the direct conversation with the resolved id (no copying).
      const conv = await apiCreateConversation({
        type: "direct",
        participant_user_ids: [hit.id],
        name: null,
      });
      set((state) => ({
        conversations: sortConversations([
          conv,
          ...state.conversations.filter((c) => c.id !== conv.id),
        ]),
        activeConversationId: conv.id,
        peerUsernameById: { ...state.peerUsernameById, [hit.id]: hit.username },
      }));
      return conv.id;
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "failed to create conversation" });
      return null;
    }
  },

  async startGroup(name, usernames) {
    const identity = get().identity;
    if (!identity) {
      set({ error: "not ready to create a group" });
      return null;
    }
    const groupName = name.trim();
    if (!groupName) {
      set({ error: "Enter a name for the group." });
      return null;
    }
    const handles = usernames.map((u) => u.trim()).filter(Boolean);
    if (!handles.length) {
      set({ error: "Add at least one member to the group." });
      return null;
    }
    try {
      // 1. Resolve every handle to a user id, same directory step as US2.
      const resolved: Array<{ id: string; username: string }> = [];
      for (const handle of handles) {
        const matches = await searchUsers(handle);
        const hit = matches.find((m) => m.username.toLowerCase() === handle.toLowerCase());
        if (!hit) {
          set({ error: `No user found with the username “${handle}”.` });
          return null;
        }
        resolved.push(hit);
      }
      // 2. Resolve every member's identity key (needed to wrap epoch 1 for
      //    them) BEFORE creating anything server-side. This must happen
      //    first: if any member hasn't published identity keys yet (they've
      //    registered but never signed in), we'd otherwise create the group
      //    on the server, then fail here — leaving a "zombie" group that
      //    exists for every invited member but has NO epoch key ever
      //    established, so opening it later always fails with "this group's
      //    encryption key hasn't been established on this device yet" with
      //    no way to recover. Fail fast instead, before any state exists.
      const recipients = await Promise.all(
        resolved.map(async (r) => {
          const key = await fetchPeerIdentityKey(r.id, r.username);
          return { identityKeyId: key.keyId, kemPublicKey: key.kemPublicKey };
        }),
      );
      // 3. Create the group (creator becomes group_admin).
      const conv = await apiCreateConversation({
        type: "group",
        participant_user_ids: resolved.map((r) => r.id),
        name: groupName,
      });
      // 4. Distribute epoch 1 to every other member. If this still fails
      //    (e.g. a transient network error — every member's key is already
      //    confirmed to exist by step 2), best-effort undo the just-created
      //    group so it doesn't linger keyless in the creator's rail, then
      //    surface a clear retry-able error instead of a broken group.
      try {
        await distributeNewGroupEpoch(conv.id, identity, recipients);
      } catch (distributeErr) {
        await apiDeleteConversation(conv.id).catch(() => {
          // Best-effort only — even if the cleanup call itself fails, the
          // original error below is what the user needs to see and retry.
        });
        throw distributeErr;
      }

      set((state) => ({
        conversations: sortConversations([
          conv,
          ...state.conversations.filter((c) => c.id !== conv.id),
        ]),
        activeConversationId: conv.id,
        peerUsernameById: {
          ...state.peerUsernameById,
          ...Object.fromEntries(resolved.map((r) => [r.id, r.username])),
        },
      }));
      return conv.id;
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "failed to create group" });
      return null;
    }
  },

  async addGroupMember(conversationId, username) {
    const identity = get().identity;
    if (!identity) {
      set({ error: "not ready" });
      return false;
    }
    const handle = username.trim();
    if (!handle) {
      set({ error: "Enter a username to add." });
      return false;
    }
    try {
      const matches = await searchUsers(handle);
      const hit = matches.find((m) => m.username.toLowerCase() === handle.toLowerCase());
      if (!hit) {
        set({ error: `No user found with the username “${handle}”.` });
        return false;
      }
      // Confirm the new member has published identity keys BEFORE adding
      // them server-side — otherwise a member without keys yet gets added,
      // the rekey below fails trying to wrap for them, and they're left in
      // the group with no epoch key ever distributed to them (same class of
      // bug as the create-group ordering fix above).
      await fetchPeerIdentityKey(hit.id, hit.username);
      await apiAddParticipant(conversationId, { user_id: hit.id });
      await get().refreshConversations();

      // Rekey: every currently-active member (including the just-added one)
      // gets the new epoch; nobody outside the group can ever obtain it.
      const conv = get().conversations.find((c) => c.id === conversationId);
      const memberIds = conv?.participants.map((p) => p.user_id) ?? [hit.id];
      const peerUsernameById = get().peerUsernameById;
      const recipients = await Promise.all(
        memberIds
          .filter((id) => id !== useAuthStore.getState().session?.userId)
          .map(async (id) => {
            const key = await fetchPeerIdentityKey(id, peerUsernameById[id] ?? id);
            return { identityKeyId: key.keyId, kemPublicKey: key.kemPublicKey };
          }),
      );
      await distributeNewGroupEpoch(conversationId, identity, recipients);
      set((state) => ({
        peerUsernameById: { ...state.peerUsernameById, [hit.id]: hit.username },
      }));
      return true;
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "failed to add member" });
      return false;
    }
  },

  async removeGroupMember(conversationId, userId) {
    const identity = get().identity;
    if (!identity) {
      set({ error: "not ready" });
      return false;
    }
    try {
      await apiRemoveParticipant(conversationId, userId);
      await get().refreshConversations();

      // Rekey to exclude the removed member — the crypto-level enforcement of
      // FR-028: they never receive this epoch's key.
      const conv = get().conversations.find((c) => c.id === conversationId);
      const remainingIds = (conv?.participants ?? [])
        .map((p) => p.user_id)
        .filter((id) => id !== useAuthStore.getState().session?.userId);
      if (remainingIds.length > 0) {
        const peerUsernameById = get().peerUsernameById;
        const recipients = await Promise.all(
          remainingIds.map(async (id) => {
            const key = await fetchPeerIdentityKey(id, peerUsernameById[id] ?? id);
            return { identityKeyId: key.keyId, kemPublicKey: key.kemPublicKey };
          }),
        );
        await distributeNewGroupEpoch(conversationId, identity, recipients);
      }
      return true;
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "failed to remove member" });
      return false;
    }
  },

  async rekeyGroup(conversationId) {
    const identity = get().identity;
    if (!identity) {
      set({ error: "not ready" });
      return false;
    }
    const conv = get().conversations.find((c) => c.id === conversationId);
    if (!conv || conv.type !== "group") {
      set({ error: "only a group can be re-keyed" });
      return false;
    }
    try {
      const selfUserId = useAuthStore.getState().session?.userId ?? "";
      // Base the new epoch on the group's ACTUAL current epoch — the highest
      // epoch seen in the message history (plaintext `envelope.epoch` metadata,
      // visible even when the device can't decrypt the content) — so the new
      // epoch is strictly greater than any existing one even when this device
      // holds no prior key (e.g. after an identity rotation). Using only this
      // device's stored epoch would reset to 1 and collide with / overwrite an
      // existing epoch 1, destroying other members' ability to read old messages.
      const messages = get().messagesByConversation[conversationId] ?? [];
      let baseEpoch = groupKeyStore.getCurrentEpoch(conversationId) ?? 0;
      for (const m of messages) {
        const e = m.envelope.epoch;
        if (typeof e === "number" && e > baseEpoch) baseEpoch = e;
      }
      const memberIds = conv.participants
        .map((p) => p.user_id)
        .filter((id) => id !== selfUserId);
      const peerUsernameById = get().peerUsernameById;
      const recipients = await Promise.all(
        memberIds.map(async (id) => {
          const key = await fetchPeerIdentityKey(id, peerUsernameById[id] ?? id);
          return { identityKeyId: key.keyId, kemPublicKey: key.kemPublicKey };
        }),
      );
      await distributeNewGroupEpoch(conversationId, identity, recipients, baseEpoch);
      // Re-sync the thread so the new epoch key is absorbed and the rail preview
      // refreshes; the creator already holds the new key (stored by
      // `distributeNewGroupEpoch`), so sending works immediately after this.
      await get().selectConversation(conversationId);
      return true;
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "failed to re-key group" });
      return false;
    }
  },

  async deleteConversation(conversationId) {
    const conv = get().conversations.find((c) => c.id === conversationId);
    try {
      // Direct conversations are hard-deleted server-side (conversation row +
      // both memberships + every message, via cascade); group conversations
      // stay a per-user soft delete (leave), since a hard delete there would
      // destroy the group for every other member (FR-055/US3).
      await apiDeleteConversation(conversationId);
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "failed to delete conversation" });
      return false;
    }
    // Drop local state: remove from the rail, clear the decrypted log + preview,
    // and deselect if it was active.
    if (conv?.type !== "group") {
      // The server-side conversation (and its id) is gone for good — re-adding
      // the same contact creates a brand-new conversation id, so the old local
      // key is dead weight; clearing it forces a fresh ML-KEM-768 exchange
      // instead of leaving a stale, orphaned entry in localStorage.
      conversationKeyStore.clear(conversationId);
    } else {
      groupKeyStore.clear(conversationId);
    }
    const state = get();
    const remainingMessages = { ...state.messagesByConversation };
    delete remainingMessages[conversationId];
    const remainingPreviews = { ...state.lastMessagePreviewByConversation };
    delete remainingPreviews[conversationId];
    set((s) => ({
      conversations: s.conversations.filter((c) => c.id !== conversationId),
      messagesByConversation: remainingMessages,
      lastMessagePreviewByConversation: remainingPreviews,
      activeConversationId:
        s.activeConversationId === conversationId ? null : s.activeConversationId,
    }));
    return true;
  },

  async sendOutgoing(plaintext) {
    const state = get();
    const identity = state.identity;
    const convId = state.activeConversationId;
    if (!identity || !convId) {
      set({ error: "not ready to send" });
      return;
    }
    const conv = state.conversations.find((c) => c.id === convId);
    if (!conv) {
      set({ error: "active conversation not found" });
      return;
    }
    set({ sending: true, error: null });
    try {
      let ciphertextB64: string;
      let envelope: MessageEnvelope;

      if (conv.type === "group") {
        const epoch = groupKeyStore.getCurrentEpoch(convId);
        const key = epoch !== null ? groupKeyStore.getKey(convId, epoch) : null;
        if (epoch === null || !key) {
          throw new Error("this group's encryption key hasn't been established on this device yet");
        }
        const plaintextBytes = new TextEncoder().encode(plaintext);
        const sealed = await sealGroupMessage(
          key,
          plaintextBytes,
          identity.signingPrivateKey,
          convId,
          identity.keyId,
          epoch,
        );
        ciphertextB64 = bytesToBase64(sealed.ciphertext);
        envelope = {
          alg: "aes-256-gcm",
          nonce: bytesToBase64(sealed.nonce),
          version: 1,
          sig: bytesToBase64(sealed.signature),
          epoch,
        };
      } else {
        const selfUserId = useAuthStore.getState().session?.userId ?? "";
        const peerUserId = otherParticipantUserId(conv, selfUserId);
        // Check the server-side backup (not just the local cache) before
        // deciding to self-initiate — this recovers a key this device
        // established as the ORIGINAL INITIATOR on another (or a since-
        // storage-cleared) browser, which can never be re-derived from
        // message history alone (see `resolveConversationKey`).
        const existingKey = await resolveConversationKey(convId, identity);
        const peer = existingKey ? null : await fetchPeerPublicKeys(peerUserId);
        const plaintextBytes = new TextEncoder().encode(plaintext);
        const { prepared, key } = await prepareOutgoing(
          convId,
          peer,
          plaintextBytes,
          identity,
          existingKey,
        );
        // Guard a TOCTOU race: `existingKey` was read before the awaits above,
        // so an incoming keying message (`ingestRealtimeMessage` → `openIncoming`)
        // may have landed in between and already stored a fresher, authoritative
        // key for this conversation. Don't clobber it with the key we just
        // derived here — this message is already sealed under `key` (with its
        // own embedded KEM ciphertext if it's a keying message), so the
        // recipient decrypts it correctly regardless; only the LOCAL cache for
        // subsequent sends is at stake.
        if (existingKey || !conversationKeyStore.get(convId)) {
          conversationKeyStore.set(convId, key);
        }
        if (prepared.keying) {
          // We just self-initiated a brand-new key — back it up immediately so
          // clearing this browser's storage later doesn't lose it (we are the
          // one side that can never re-derive it from message history alone).
          void backupConversationKey(convId, identity, key);
        }
        ciphertextB64 = prepared.ciphertextB64;
        envelope = prepared.envelope;
      }

      const sent = await apiSendMessage(convId, {
        ciphertext: ciphertextB64,
        envelope,
        sender_identity_key_id: identity.keyId,
      });

      // The sender already holds the plaintext (we just encrypted it), so cache
      // it directly — otherwise the thread would show "Decrypting…" forever for
      // our own message (the WS does not echo back to the sender, so nothing
      // else populates the cache for it).
      decryptedCache.set(sent.id, plaintext);

      // Optimistically append the locally-sent message so the thread updates
      // immediately (the WS does not echo back to the sender). FR-058: this is
      // now the latest message — bump the rail preview + the conversation's
      // last_message_at and re-sort so the active chat rises to the top.
      set((s) => {
        const conversations = sortConversations(
          s.conversations.map((c) =>
            c.id === convId ? { ...c, last_message_at: sent.sent_at } : c,
          ),
        );
        return {
          sending: false,
          conversations,
          messagesByConversation: {
            ...s.messagesByConversation,
            [convId]: [...(s.messagesByConversation[convId] ?? []), sent],
          },
          lastMessagePreviewByConversation: {
            ...s.lastMessagePreviewByConversation,
            [convId]: plaintext,
          },
        };
      });
    } catch (err) {
      set({ sending: false, error: err instanceof Error ? err.message : "failed to send" });
    }
  },

  async sendFile(file) {
    const state = get();
    const identity = state.identity;
    const convId = state.activeConversationId;
    if (!identity || !convId) {
      set({ error: "not ready to send" });
      return;
    }
    const conv = state.conversations.find((c) => c.id === convId);
    if (!conv) {
      set({ error: "active conversation not found" });
      return;
    }
    const validation = validateFileForUpload(file);
    if (!validation.ok) {
      set({ error: validation.reason ?? "file not allowed" });
      return;
    }

    set({ sending: true, error: null });
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const plaintext = packFilePlaintext(file.name, bytes);

      let ciphertext: Uint8Array;
      let fileEnvelope: MessageEnvelope;

      if (conv.type === "group") {
        const epoch = groupKeyStore.getCurrentEpoch(convId);
        const key = epoch !== null ? groupKeyStore.getKey(convId, epoch) : null;
        if (epoch === null || !key) {
          throw new Error("this group's encryption key hasn't been established on this device yet");
        }
        const sealed = await sealGroupMessage(
          key,
          plaintext,
          identity.signingPrivateKey,
          convId,
          identity.keyId,
          epoch,
        );
        ciphertext = sealed.ciphertext;
        fileEnvelope = {
          alg: "aes-256-gcm",
          nonce: bytesToBase64(sealed.nonce),
          version: 1,
          sig: bytesToBase64(sealed.signature),
          epoch,
        };
      } else {
        // Files reuse the conversation's already-established message key —
        // there is no keying dance here (unlike text messages via
        // `prepareOutgoing`): a brand-new conversation must exchange at least
        // one text message first so a key exists to encrypt the file under.
        const existingKey = await resolveConversationKey(convId, identity);
        if (!existingKey) {
          throw new Error(
            "Send a text message first to set up encryption for this conversation, then you can share files.",
          );
        }
        const sealed = await sealFile(
          existingKey.messageKey,
          plaintext,
          identity.signingPrivateKey,
          convId,
          identity.keyId,
        );
        ciphertext = sealed.ciphertext;
        fileEnvelope = sealed.envelope;
      }

      const uploaded = await apiUploadFile(convId, {
        senderIdentityKeyId: identity.keyId,
        fileEnvelope,
        contentType: validation.contentType,
        ciphertext,
      });

      // We already hold the plaintext bytes (we just encrypted them) — cache
      // the decrypted file immediately so the sender's own bubble renders
      // without a round-trip download (mirrors sendOutgoing's decryptedCache
      // seeding for text messages).
      decryptedFileCache.set(uploaded.message_id, {
        filename: file.name,
        blob: new Blob([bytes.slice()], { type: validation.contentType }),
        contentType: validation.contentType,
      });

      const record: MessageResponse = {
        id: uploaded.message_id,
        conversation_id: convId,
        sender_id: useAuthStore.getState().session?.userId ?? "",
        sender_identity_key_id: identity.keyId,
        ciphertext: "",
        envelope: {
          ...fileEnvelope,
          kind: "file",
          file_attachment_id: uploaded.file_attachment_id,
        },
        sent_at: uploaded.sent_at,
      };

      set((s) => {
        const conversations = sortConversations(
          s.conversations.map((c) =>
            c.id === convId ? { ...c, last_message_at: uploaded.sent_at } : c,
          ),
        );
        return {
          sending: false,
          fileCacheVersion: s.fileCacheVersion + 1,
          conversations,
          messagesByConversation: {
            ...s.messagesByConversation,
            [convId]: [...(s.messagesByConversation[convId] ?? []), record],
          },
          lastMessagePreviewByConversation: {
            ...s.lastMessagePreviewByConversation,
            [convId]: `📎 ${file.name}`,
          },
        };
      });
    } catch (err) {
      set({ sending: false, error: err instanceof Error ? err.message : "failed to send file" });
    }
  },

  async loadFile(conversationId, message) {
    if (decryptedFileCache.has(message.id) || fileLoadErrors.has(message.id)) return;
    const identity = get().identity;
    const conv = get().conversations.find((c) => c.id === conversationId);
    const fileAttachmentId = message.envelope.file_attachment_id;
    if (!identity || !conv || typeof fileAttachmentId !== "string") return;

    try {
      const { ciphertext, envelope, contentType } = await apiDownloadFile(
        conversationId,
        fileAttachmentId,
      );
      const senderSigningPublicKey = await fetchSenderSigningKey(
        message.sender_id,
        message.sender_identity_key_id,
      );

      let filename: string;
      let bytes: Uint8Array;
      if (conv.type === "group") {
        const epoch = envelope.epoch;
        if (typeof epoch !== "number") throw new Error("group file missing epoch");
        const key = groupKeyStore.getKey(conversationId, epoch);
        if (!key) {
          throw new Error(`no group key for epoch ${epoch} — you may have joined after this file`);
        }
        const nonce = base64ToBytes(String(envelope.nonce));
        const signature = base64ToBytes(String(envelope.sig));
        const plaintext = await openGroupMessage(
          key,
          ciphertext,
          nonce,
          signature,
          senderSigningPublicKey,
          conversationId,
          message.sender_identity_key_id,
          epoch,
        );
        ({ filename, bytes } = unpackFilePlaintext(plaintext));
      } else {
        const key = await resolveConversationKey(conversationId, identity);
        if (!key) throw new Error("no key established for this conversation yet");
        ({ filename, bytes } = await openFile(
          key.messageKey,
          ciphertext,
          envelope,
          senderSigningPublicKey,
          conversationId,
          message.sender_identity_key_id,
        ));
      }

      decryptedFileCache.set(message.id, {
        filename,
        blob: new Blob([bytes.slice()], { type: contentType }),
        contentType,
      });
      set((s) => ({ fileCacheVersion: s.fileCacheVersion + 1 }));
    } catch (err) {
      fileLoadErrors.set(message.id, err instanceof Error ? err.message : "failed to load file");
      set((s) => ({ fileCacheVersion: s.fileCacheVersion + 1 }));
    }
  },

  async ingestRealtimeMessage(data) {
    const convId = data.conversation_id;
    const state = get();
    const identity = state.identity;
    if (!identity) return;

    // FR-057: if this conversation is not in our list (the peer reactivated a
    // chat we had left, or started a brand-new one), refresh the list first so
    // it appears — the message is still ingested below regardless.
    if (!state.conversations.some((c) => c.id === convId)) {
      await get().refreshConversations();
    }

    const record: MessageResponse = {
      id: data.message_id,
      conversation_id: convId,
      sender_id: data.sender_id,
      sender_identity_key_id: data.sender_identity_key_id,
      ciphertext: data.ciphertext,
      envelope: data.envelope,
      sent_at: data.sent_at,
    };
    const conv = get().conversations.find((c) => c.id === convId);
    // A group key-distribution record is never shown as a chat bubble (US3) —
    // it's still processed below to absorb the epoch key, just not appended
    // to the displayed thread.
    if (!conv || !isKeyDistributionMessage(conv, record)) {
      set((s) => ({
        messagesByConversation: {
          ...s.messagesByConversation,
          [convId]: [...(s.messagesByConversation[convId] ?? []), record],
        },
      }));
    }

    try {
      if (!conv) return; // refreshed above but still missing — nothing to open against
      const text = await openIncomingForConversation(conv, record, identity, fetchSenderSigningKey);
      if (text === null) {
        // A group key-distribution message (or a wrap not addressed to us) —
        // key material absorbed above, nothing to display.
        return;
      }
      // Tag the decrypted record with plaintext via a side-channel map the UI
      // reads (avoids storing plaintext inside the MessageResponse envelope).
      decryptedCache.set(record.id, text);
      // FR-057/FR-058: refresh the rail without a full reload — bump the
      // preview to the just-decrypted message, advance the conversation's
      // last_message_at, and re-sort so the chat rises to the top.
      set((s) => {
        const conversations = sortConversations(
          s.conversations.map((c) =>
            c.id === convId ? { ...c, last_message_at: data.sent_at } : c,
          ),
        );
        return {
          conversations,
          lastMessagePreviewByConversation: {
            ...s.lastMessagePreviewByConversation,
            [convId]: text,
          },
        };
      });
    } catch (err) {
      decryptErrors.set(record.id, err instanceof Error ? err.message : "decrypt failed");
    }
  },

  setRealtimeStatus(status) {
    set({ realtimeStatus: status });
  },

  async onGroupMembershipChanged(conversationId) {
    // T068: a group's membership changed (add/remove) — refresh the list so
    // the member panel is current, and if this conversation is open, re-load
    // its messages so the accompanying key-distribution message (sent by
    // whoever performed the change) is picked up and decrypted going forward.
    await get().refreshConversations();

    // The event fired for OUR OWN removal (or any other reason we're no
    // longer an active participant): `list_for_user` no longer returns this
    // conversation. Attempting to fetch its messages would just 403 — drop
    // any local state for it instead, rather than trying (and failing) a
    // fetch we already know is unauthorized.
    if (!get().conversations.some((c) => c.id === conversationId)) {
      conversationKeyStore.clear(conversationId);
      groupKeyStore.clear(conversationId);
      const state = get();
      const remainingMessages = { ...state.messagesByConversation };
      delete remainingMessages[conversationId];
      const remainingPreviews = { ...state.lastMessagePreviewByConversation };
      delete remainingPreviews[conversationId];
      set((s) => ({
        messagesByConversation: remainingMessages,
        lastMessagePreviewByConversation: remainingPreviews,
        activeConversationId:
          s.activeConversationId === conversationId ? null : s.activeConversationId,
      }));
      return;
    }

    if (get().activeConversationId === conversationId) {
      await get().selectConversation(conversationId);
    }
  },

  clearError() {
    set({ error: null });
  },
}));

// ---- Decrypted-plaintext side cache (kept out of persisted/state shape) ----
// Plaintext lives only here, in memory, keyed by message id. It is never sent to
// the backend and never persisted to localStorage (FR-051).
const decryptedCache = new Map<string, string>();
const decryptErrors = new Map<string, string>();

export function getDecryptedText(messageId: string): string | null {
  return decryptedCache.get(messageId) ?? null;
}

export function getDecryptError(messageId: string): string | null {
  return decryptErrors.get(messageId) ?? null;
}

/** Decrypted file/image share, kept in memory only (FR-051) — same rationale
 * as `decryptedCache`, populated lazily by the `loadFile` store action rather
 * than eagerly for every file in a conversation's history. */
export interface DecryptedFile {
  filename: string;
  blob: Blob;
  contentType: string;
}
const decryptedFileCache = new Map<string, DecryptedFile>();
const fileLoadErrors = new Map<string, string>();

export function getDecryptedFile(messageId: string): DecryptedFile | null {
  return decryptedFileCache.get(messageId) ?? null;
}

export function getFileLoadError(messageId: string): string | null {
  return fileLoadErrors.get(messageId) ?? null;
}

/**
 * Decrypt the full message log of a conversation on open (lazy, in-memory).
 * Messages MUST be processed in order (oldest-first, as the API returns them)
 * for groups: a key-distribution record must be absorbed before a later
 * message sealed under that epoch can be opened.
 */
export async function decryptConversationLog(
  conv: ConversationResponse,
  messages: MessageResponse[],
  identity: LocalIdentity,
): Promise<number> {
  // Pre-join group messages are already hidden from the displayed log by
  // `selectConversation`'s filter, and their epoch key was never addressed to
  // this device — skip them here too so they neither decrypt-fail nor get
  // counted as no-key losses (they have their own "you were added" notice).
  const selfUserId = useAuthStore.getState().session?.userId ?? "";
  const me = conv.type === "group" ? conv.participants.find((p) => p.user_id === selfUserId) : null;
  const joinedMs = me ? Date.parse(me.joined_at) : NaN;
  let noKeyCount = 0;
  for (const message of messages) {
    if (decryptedCache.has(message.id)) continue;
    if (me && Number.isFinite(joinedMs)) {
      const sentMs = Date.parse(message.sent_at);
      if (Number.isFinite(sentMs) && sentMs < joinedMs) continue;
    }
    try {
      const text = await openIncomingForConversation(
        conv,
        message,
        identity,
        fetchSenderSigningKey,
      );
      if (text !== null) decryptedCache.set(message.id, text);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "decrypt failed";
      // A group content message whose epoch key this device doesn't hold
      // (e.g. after an identity rotation — the old epoch key was wrapped for
      // the now-superseded keypair) genuinely can't be decrypted. Rendering a
      // per-row "Couldn't decrypt … no group key for epoch N" bubble is wrong;
      // skip it silently and count it for a single thread notice instead.
      if (conv.type === "group" && /no group key for epoch/.test(msg)) {
        noKeyCount += 1;
        continue;
      }
      decryptErrors.set(message.id, msg);
    }
  }
  return noKeyCount;
}

/** Test-only: reset the in-memory plaintext caches between tests. */
export function __resetDecryptCaches(): void {
  decryptedCache.clear();
  decryptErrors.clear();
  decryptedFileCache.clear();
  fileLoadErrors.clear();
  senderSigningKeyCache.clear();
}