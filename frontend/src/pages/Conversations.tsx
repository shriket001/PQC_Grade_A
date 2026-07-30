/**
 * Conversations page — the E2EE 1:1 messaging surface (US2 / Phase 5).
 *
 * Left rail: conversation list + start-a-conversation. Right pane: the active
 * thread with decrypted messages and a composer. Realtime `message.new` events
 * arrive over the WebSocket and are ingested (decrypted in-browser) into the
 * thread. All crypto happens behind `src/crypto/` — this component only ever
 * holds plaintext already decrypted by the store (FR-051/SC-002).
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";

import { Button } from "@/components/Button";
import { DevicesModal } from "@/components/DevicesModal";
import { FormField } from "@/components/FormField";
import { LatticeField } from "@/components/LatticeField";
import { Menu, type MenuItem } from "@/components/Menu";
import { MfaSettingsModal } from "@/components/MfaSettingsModal";
import { Modal } from "@/components/Modal";
import { Textarea } from "@/components/Textarea";
import { UserPicker } from "@/components/UserPicker";
import { useRealtime } from "@/hooks/useRealtime";
import { useTheme } from "@/hooks/useTheme";
import { logout } from "@/services/authService";
import { useAuthStore } from "@/store/authStore";
import {
  getDecryptedFile,
  getDecryptedText,
  getDecryptError,
  getFileLoadError,
  isFileMessage,
  useMessagingStore,
} from "@/store/messagingStore";
import type { ConversationParticipantResponse, MessageResponse } from "@/types/messaging";
import type { UserSummaryResponse } from "@/types/user";

// Coarse client-side hint for the file picker; the authoritative allowlist +
// size cap is `fileCrypto.validateFileForUpload`, enforced in the store.
const FILE_INPUT_ACCEPT = [".pdf", "image/*"].join(",");

/** FR-058: compact last-activity time for the rail — HH:MM today, else mon/day. */
function formatConvTime(iso: string): string {
  const d = new Date(iso);
  const now = new Date();
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  if (sameDay) {
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

/** FR-058: one-line rail preview, truncated to keep the row to two lines. */
function truncatePreview(text: string, max = 48): string {
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length > max ? `${oneLine.slice(0, max - 1)}…` : oneLine;
}

/**
 * Render a participant's display label from the resolved-username map, falling
 * back to a neutral placeholder when the name isn't known yet. NEVER falls
 * back to a raw `user_id` prefix — that produced the `e2b0aa5d` truncated-id
 * flash on refresh (and a permanent fragment when resolution failed). The
 * server now ships `username` on each participant, so the map is populated
 * synchronously from the conversation payload; this placeholder only shows
 * for a participant that somehow arrived without a name and couldn't be
 * resolved by the store's backstop fetch.
 */
function peerLabel(usernameById: Record<string, string>, userId: string): string {
  return usernameById[userId] ?? "Unknown user";
}

/** Two-letter avatar glyph for a conversation row: the peer's initials for a
 * direct chat, a hash for a group. Purely cosmetic — the avatar is never a
 * control (the delete/leave action lives in the row's kebab menu, not on the
 * avatar), which is why the old bare `×` on each row was removed. */
function avatarGlyph(label: string, isGroup: boolean): string {
  if (isGroup) return "#";
  const cleaned = label.replace(/^@/, "");
  return (cleaned.slice(0, 2) || "?").toUpperCase();
}

export default function Conversations(): JSX.Element {
  const session = useAuthStore((s) => s.session);
  const signOut = useAuthStore((s) => s.signOut);
  const navigate = useNavigate();
  const { toggleTheme } = useTheme();

  const conversations = useMessagingStore((s) => s.conversations);
  const activeId = useMessagingStore((s) => s.activeConversationId);
  const messagesByConversation = useMessagingStore((s) => s.messagesByConversation);
  const peerUsernameById = useMessagingStore((s) => s.peerUsernameById);
  const lastMessagePreviewByConversation = useMessagingStore(
    (s) => s.lastMessagePreviewByConversation,
  );
  const hiddenPreJoinCountByConversation = useMessagingStore(
    (s) => s.hiddenPreJoinCountByConversation,
  );
  const hiddenNoKeyCountByConversation = useMessagingStore(
    (s) => s.hiddenNoKeyCountByConversation,
  );
  const realtimeStatus = useMessagingStore((s) => s.realtimeStatus);
  const error = useMessagingStore((s) => s.error);
  const sending = useMessagingStore((s) => s.sending);
  const identityLocked = useMessagingStore((s) => s.identityLocked);
  const identityFirstTimeSetup = useMessagingStore((s) => s.identityFirstTimeSetup);
  const bootstrap = useMessagingStore((s) => s.bootstrap);
  const unlockWithPassword = useMessagingStore((s) => s.unlockWithPassword);
  const selectConversation = useMessagingStore((s) => s.selectConversation);
  const startConversation = useMessagingStore((s) => s.startConversation);
  const startGroup = useMessagingStore((s) => s.startGroup);
  const addGroupMember = useMessagingStore((s) => s.addGroupMember);
  const removeGroupMember = useMessagingStore((s) => s.removeGroupMember);
  const rekeyGroup = useMessagingStore((s) => s.rekeyGroup);
  const deleteConversation = useMessagingStore((s) => s.deleteConversation);
  const sendOutgoing = useMessagingStore((s) => s.sendOutgoing);
  const sendFile = useMessagingStore((s) => s.sendFile);
  const loadFile = useMessagingStore((s) => s.loadFile);
  const retryLoadFile = useMessagingStore((s) => s.retryLoadFile);
  const ingestRealtimeMessage = useMessagingStore((s) => s.ingestRealtimeMessage);
  const setRealtimeStatus = useMessagingStore((s) => s.setRealtimeStatus);
  const onGroupMembershipChanged = useMessagingStore((s) => s.onGroupMembershipChanged);
  const clearError = useMessagingStore((s) => s.clearError);

  const [draft, setDraft] = useState("");
  const [filterQuery, setFilterQuery] = useState("");
  const [newPeerSelection, setNewPeerSelection] = useState<UserSummaryResponse[]>([]);
  const [startingConversation, setStartingConversation] = useState(false);
  const [showNewGroup, setShowNewGroup] = useState(false);
  const [showMfaSettings, setShowMfaSettings] = useState(false);
  const [showDevices, setShowDevices] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupMembers, setNewGroupMembers] = useState<UserSummaryResponse[]>([]);
  const [newGroupBusy, setNewGroupBusy] = useState(false);
  const [addMemberSelection, setAddMemberSelection] = useState<UserSummaryResponse[]>([]);
  const [addingMember, setAddingMember] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [, forceRender] = useState(0);

  // Synchronous re-entrancy guards: a burst of rapid clicks/Enter-presses can
  // fire multiple submit events before React commits a state-driven `disabled`
  // update, which would otherwise create duplicate conversations/groups.
  const startingConversationRef = useRef(false);
  const creatingGroupRef = useRef(false);
  const addingMemberRef = useRef(false);

  // Boot identity + conversation list once on mount.
  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  // Realtime connection for the session lifetime.
  useRealtime(ingestRealtimeMessage, setRealtimeStatus, (data) =>
    void onGroupMembershipChanged(data.conversation_id),
  );

  // Re-render after async decryption completes so decrypted text appears.
  useEffect(() => {
    const id = window.setInterval(() => forceRender((n) => n + 1), 250);
    return () => window.clearInterval(id);
  }, []);

  // Client-side conversation filter (WhatsApp-style "search chats" box). The
  // server stays content-agnostic; this only narrows the already-loaded list.
  // Declared before the early returns so the hook order is stable across renders.
  const selfUserIdForFilter = session?.userId ?? "";
  const filteredConversations = useMemo(() => {
    const q = filterQuery.trim().toLowerCase();
    if (!q) return conversations;
    return conversations.filter((c) => {
      const isGroup = c.type === "group";
      const peer = isGroup ? null : c.participants.find((p) => p.user_id !== selfUserIdForFilter);
      const label = isGroup
        ? (c.name ?? "Group")
        : peer
          ? peerLabel(peerUsernameById, peer.user_id)
          : "direct";
      return label.toLowerCase().includes(q);
    });
  }, [conversations, filterQuery, peerUsernameById, selfUserIdForFilter]);

  async function handleLogout(): Promise<void> {
    try {
      await logout();
    } catch {
      // Clear local state regardless of server response.
    }
    signOut();
    navigate("/login", { replace: true });
  }

  async function handleStartConversation(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    // Synchronous guard: blocks a burst of rapid submits even before React
    // commits the `startingConversation`-driven disabled state.
    if (startingConversationRef.current) return;
    const peer = newPeerSelection[0];
    if (!peer) return;
    startingConversationRef.current = true;
    setStartingConversation(true);
    try {
      const id = await startConversation(peer.username);
      if (id) {
        setNewPeerSelection([]);
        await selectConversation(id);
      }
    } finally {
      startingConversationRef.current = false;
      setStartingConversation(false);
    }
  }

  async function handleStartGroup(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    if (creatingGroupRef.current) return;
    if (!newGroupName.trim() || newGroupMembers.length === 0) return;
    creatingGroupRef.current = true;
    setNewGroupBusy(true);
    try {
      const usernames = newGroupMembers.map((u) => u.username);
      const id = await startGroup(newGroupName, usernames);
      if (id) {
        setNewGroupName("");
        setNewGroupMembers([]);
        setShowNewGroup(false);
        await selectConversation(id);
      }
    } finally {
      creatingGroupRef.current = false;
      setNewGroupBusy(false);
    }
  }

  async function handleAddMember(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    if (addingMemberRef.current) return;
    const target = addMemberSelection[0];
    if (!target || !activeId) return;
    addingMemberRef.current = true;
    setAddingMember(true);
    try {
      const ok = await addGroupMember(activeId, target.username);
      if (ok) setAddMemberSelection([]);
    } finally {
      addingMemberRef.current = false;
      setAddingMember(false);
    }
  }

  async function handleRemoveMember(userId: string, label: string): Promise<void> {
    if (!activeId) return;
    const confirmed = window.confirm(
      userId === session?.userId
        ? "Leave this group? You'll stop receiving new messages."
        : `Remove ${label} from this group?`,
    );
    if (!confirmed) return;
    await removeGroupMember(activeId, userId);
  }

  async function handleLeaveGroup(conversationId: string, label: string): Promise<void> {
    if (!session) return;
    const confirmed = window.confirm(
      `Leave the group "${label}"?\nYou'll stop receiving new messages from this group.`,
    );
    if (!confirmed) return;
    // Goes through removeGroupMember so a departure always triggers a rekey
    // excluding the departing member (FR-028) — same path the in-thread group
    // panel uses, never the generic per-user-leave endpoint (which does NOT
    // rekey and would leave a departed member holding the current epoch key).
    await removeGroupMember(conversationId, session.userId);
  }

  async function handleRekeyGroup(conversationId: string): Promise<void> {
    // Recovery path for a member whose device holds no epoch key (e.g. after an
    // identity rotation): generate a fresh epoch addressed to every current
    // member's active identity key. Confirms because it issues a new group-wide
    // epoch (every member picks it up).
    const confirmed = window.confirm(
      "Re-key this group?\nA new encryption key will be issued to every current member. " +
        "Messages from before the re-key that this device can't decrypt will remain unavailable.",
    );
    if (!confirmed) return;
    await rekeyGroup(conversationId);
  }

  async function handleDeleteConversation(conversationId: string, label: string): Promise<void> {
    // FR-055 per-user soft delete (leave): only this side is affected — the
    // other person keeps their copy + history. Confirm before leaving.
    const confirmed = window.confirm(
      `Delete the conversation with ${label}?\nThis removes it from your history; the other person keeps their copy.`,
    );
    if (!confirmed) return;
    await deleteConversation(conversationId);
  }

  async function handleSend(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    const text = draft.trim();
    if (!text || !activeId) return;
    setDraft("");
    await sendOutgoing(text);
  }

  async function handleAttachFile(event: React.ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.target.files?.[0];
    // Reset immediately so selecting the same file again still fires onChange.
    event.target.value = "";
    if (!file || !activeId) return;
    await sendFile(file);
  }

  async function handleUnlock(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    const password = unlockPassword;
    if (!password) return;
    setUnlocking(true);
    try {
      await unlockWithPassword(password);
      setUnlockPassword("");
    } finally {
      setUnlocking(false);
    }
  }

  if (!session) {
    return <Navigate to="/login" replace />;
  }

  // FR-054: no cached unwrapped identity in this browser and no transient
  // password on hand (e.g. a refresh after storage clear while still signed
  // in). Gate the whole surface behind an unlock prompt until the user
  // re-enters their password, which re-derives the wrapping key and recovers
  // the identity (and all history) from the server.
  if (identityLocked) {
    return (
      <UnlockPrompt
        email={session.email}
        firstTimeSetup={identityFirstTimeSetup}
        password={unlockPassword}
        setPassword={setUnlockPassword}
        onSubmit={handleUnlock}
        unlocking={unlocking}
        error={error}
        onDismissError={clearError}
      />
    );
  }

  const activeMessages = activeId ? (messagesByConversation[activeId] ?? []) : [];
  const selfUserId = session.userId;
  const accountName = session.username || session.email;
  const initials = accountName.slice(0, 2).toUpperCase();
  const activeConv = activeId ? conversations.find((c) => c.id === activeId) : null;
  const isActiveGroup = activeConv?.type === "group";
  const activePeer =
    activeConv && !isActiveGroup
      ? activeConv.participants.find((p) => p.user_id !== selfUserId)
      : null;
  const activePeerLabel = isActiveGroup
    ? (activeConv?.name ?? "Group")
    : activePeer
      ? peerLabel(peerUsernameById, activePeer.user_id)
      : null;
  const isActiveGroupAdmin =
    isActiveGroup &&
    activeConv?.participants.find((p) => p.user_id === selfUserId)?.role === "group_admin";
  // FR-028 (UI): a single "you were added" notice replaces one decrypt-error
  // bubble per pre-join message (which the user genuinely can't decrypt).
  const showJoinedNotice =
    isActiveGroup && activeId
      ? (hiddenPreJoinCountByConversation[activeId] ?? 0) > 0
      : false;
  // A member whose device holds no epoch key (e.g. after an identity rotation)
  // can't decrypt prior group messages and couldn't send — summarize the
  // hidden rows with one notice + a "Re-key group" recovery action instead of
  // a per-row "Couldn't decrypt … no group key for epoch N" bubble.
  const showNoKeyNotice =
    isActiveGroup && activeId
      ? (hiddenNoKeyCountByConversation[activeId] ?? 0) > 0
      : false;

  return (
    <div className="conv">
      <aside className="conv__rail">
        <div className="conv__rail-head">
          <span className="wordmark">
            VAYUNX<span className="wordmark__grade">GRADE&nbsp;A</span>
          </span>
          <Button
            type="button"
            variant="ghost"
            className="conv__rail-head-action"
            onClick={() => setShowNewGroup(true)}
            title="New group"
          >
            + New group
          </Button>
        </div>

        <form className="conv__new" onSubmit={handleStartConversation}>
          <UserPicker
            mode="single"
            label="Start a conversation"
            placeholder="Search by username to start a chat…"
            selected={newPeerSelection}
            onChange={setNewPeerSelection}
            excludeIds={[selfUserId]}
            disabled={startingConversation}
          />
          <Button
            type="submit"
            variant="ghost"
            className="conv__new-submit"
            loading={startingConversation}
            disabled={!newPeerSelection.length}
            aria-label="Start chat"
            title="Start chat"
          >
            →
          </Button>
        </form>

        <div className="conv__search">
          <svg
            className="conv__search-icon"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="7" />
            <path strokeLinecap="round" d="m20 20-3.2-3.2" />
          </svg>
          <input
            type="text"
            className="conv__search-input"
            placeholder="Search chats…"
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            aria-label="Filter conversations"
          />
        </div>

        <nav className="conv__list" aria-label="Conversations">
          {conversations.length === 0 ? (
            <p className="conv__empty">No conversations yet. Start one above.</p>
          ) : filteredConversations.length === 0 ? (
            <p className="conv__empty">No conversations match “{filterQuery.trim()}”.</p>
          ) : (
            filteredConversations.map((c) => {
              const isGroup = c.type === "group";
              const peer = isGroup
                ? null
                : c.participants.find((p) => p.user_id !== selfUserId);
              const label = isGroup
                ? (c.name ?? "Group")
                : peer
                  ? peerLabel(peerUsernameById, peer.user_id)
                  : "direct";
              const preview = lastMessagePreviewByConversation[c.id] ?? "";
              const time = formatConvTime(c.last_message_at ?? c.created_at);
              const rowMenuItems: MenuItem[] = isGroup
                ? [
                    {
                      label: "Re-key group",
                      onClick: () => void handleRekeyGroup(c.id),
                    },
                    {
                      label: "Leave group",
                      danger: true,
                      onClick: () => void handleLeaveGroup(c.id, label),
                    },
                  ]
                : [
                    {
                      label: "Delete chat",
                      danger: true,
                      onClick: () => void handleDeleteConversation(c.id, label),
                    },
                  ];
              return (
                <div
                  key={c.id}
                  className={`conv__item${c.id === activeId ? " conv__item--active" : ""}`}
                >
                  <button
                    type="button"
                    className="conv__item-select"
                    onClick={() => void selectConversation(c.id)}
                    aria-label={`Open conversation with ${label}`}
                  >
                    <span className="conv__item-row">
                      <span className="conv__avatar" aria-hidden="true">
                        {avatarGlyph(label, isGroup)}
                      </span>
                      <span className="conv__item-main">
                        <span className="conv__item-top">
                          <span className="conv__item-label mono">{label}</span>
                          <span className="conv__item-time mono">{time}</span>
                        </span>
                        <span className="conv__item-preview">
                          {preview ? truncatePreview(preview) : "No messages yet"}
                        </span>
                      </span>
                    </span>
                  </button>
                  <Menu
                    ariaLabel={`Actions for ${label}`}
                    align="end"
                    items={rowMenuItems}
                    trigger={({ triggerProps }) => (
                      <button
                        type="button"
                        className="conv__item-menu"
                        title="More actions"
                        aria-label={`More actions for ${label}`}
                        {...triggerProps}
                      >
                        ⋮
                      </button>
                    )}
                  />
                </div>
              );
            })
          )}
        </nav>

        <div className="conv__account">
          <Menu
            ariaLabel="Account"
            align="end"
            header={
              <span className="conv__account-menu-head">
                {session.username || session.email}
              </span>
            }
            items={[
              {
                label: session.mfaEnabled ? "Two-factor: on" : "Set up two-factor auth",
                onClick: () => setShowMfaSettings(true),
              },
              { label: "Manage devices", onClick: () => setShowDevices(true) },
              { label: "Switch theme", onClick: toggleTheme },
              { label: "Sign out", danger: true, onClick: () => void handleLogout() },
            ]}
            trigger={({ triggerProps }) => (
              <button
                type="button"
                className="conv__account-trigger"
                title="Account"
                {...triggerProps}
              >
                <span className="conv__avatar conv__avatar--account" aria-hidden="true">
                  {initials}
                </span>
                <span className="conv__account-id">
                  <strong>{session.username || session.email}</strong>
                  <span className="mono">{session.email}</span>
                </span>
                <span className="conv__account-chev" aria-hidden="true">
                  ▾
                </span>
              </button>
            )}
          />
        </div>
        {showNewGroup ? (
          <Modal
            title="Create a group"
            onClose={() => setShowNewGroup(false)}
            dismissDisabled={newGroupBusy}
            size="md"
          >
            <form className="form" onSubmit={handleStartGroup}>
              <FormField
                name="groupName"
                label="Group name"
                placeholder="e.g. Trip Planning"
                value={newGroupName}
                onChange={(e) => setNewGroupName(e.target.value)}
                disabled={newGroupBusy}
                autoFocus
              />
              <UserPicker
                mode="multi"
                label="Members"
                placeholder="Search by username…"
                selected={newGroupMembers}
                onChange={setNewGroupMembers}
                excludeIds={[selfUserId]}
                disabled={newGroupBusy}
              />
              <Button
                type="submit"
                loading={newGroupBusy}
                disabled={!newGroupName.trim() || newGroupMembers.length === 0}
              >
                Create group
              </Button>
            </form>
          </Modal>
        ) : null}
        {showMfaSettings ? (
          <Modal title="Two-factor authentication" onClose={() => setShowMfaSettings(false)}>
            <MfaSettingsModal
              mfaEnabled={session.mfaEnabled ?? false}
              onClose={() => setShowMfaSettings(false)}
            />
          </Modal>
        ) : null}
        {showDevices ? (
          <Modal title="Active devices" onClose={() => setShowDevices(false)}>
            <DevicesModal />
          </Modal>
        ) : null}
      </aside>

      <main className="conv__main">
        {!activeId ? (
          <ThreadPlaceholder />
        ) : (
          <ActiveThread
            conversationId={activeId}
            messages={activeMessages}
            selfUserId={selfUserId}
            peerLabel={activePeerLabel}
            draft={draft}
            setDraft={setDraft}
            onSend={handleSend}
            onAttachFile={handleAttachFile}
            loadFile={loadFile}
            retryLoadFile={retryLoadFile}
            sending={sending}
            realtimeStatus={realtimeStatus}
            showJoinedNotice={showJoinedNotice}
            showNoKeyNotice={showNoKeyNotice}
            onRekeyGroup={() => void handleRekeyGroup(activeId)}
            group={
              isActiveGroup && activeConv
                ? {
                    participants: activeConv.participants,
                    isAdmin: isActiveGroupAdmin,
                    peerUsernameById,
                    addMemberSelection,
                    setAddMemberSelection,
                    addingMember,
                    onAddMember: handleAddMember,
                    onRemoveMember: handleRemoveMember,
                  }
                : null
            }
          />
        )}

        {error ? (
          <div className="conv__toast">
            <div className="alert" role="alert">
              <span className="alert__label">Error</span>
              <span style={{ flex: 1 }}>{error}</span>
              <button type="button" className="alert-close" onClick={clearError}>
                Dismiss
              </button>
            </div>
          </div>
        ) : null}
      </main>
    </div>
  );
}

interface UnlockPromptProps {
  email: string;
  /** True when this account has never wrapped+published an E2EE identity
   * before (always true for a brand-new OAuth/Google account, which has no
   * password of its own) — swaps the copy from "enter" to "choose". */
  firstTimeSetup: boolean;
  password: string;
  setPassword: (v: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  unlocking: boolean;
  error: string | null;
  onDismissError: () => void;
}

function UnlockPrompt(props: UnlockPromptProps): JSX.Element {
  const {
    email,
    firstTimeSetup,
    password,
    setPassword,
    onSubmit,
    unlocking,
    error,
    onDismissError,
  } = props;
  return (
    <div className="conv__unlock">
      <div className="conv__unlock-card">
        <LatticeField variant="feature" />
        <div style={{ position: "relative", zIndex: 1, maxWidth: "44ch" }}>
          <h2 className="conv__placeholder-title">
            {firstTimeSetup ? "Protect your encrypted messages." : "Unlock your messages."}
          </h2>
          <p className="conv__placeholder-body">
            {firstTimeSetup ? (
              <>
                Choose a password to protect your encryption keys — this is separate from any
                password you use to sign in (including Google), and isn&apos;t sent to or stored by
                the server in usable form. You&apos;ll need to remember it to read your messages on
                any other browser or device.
              </>
            ) : (
              <>
                Your encryption keys are wrapped with your password and stored on the server. Enter
                your password to unwrap them on this browser and read your conversations.
              </>
            )}
          </p>
          <p className="mono" style={{ color: "var(--ink-faint)", fontSize: "0.8rem", marginTop: 0 }}>
            Signed in as {email}
          </p>
          <form className="form" onSubmit={onSubmit} noValidate>
            {error ? (
              <div className="alert" role="alert">
                <span className="alert__label">Error</span>
                <span style={{ flex: 1 }}>{error}</span>
                <button type="button" className="alert-close" onClick={onDismissError}>
                  Dismiss
                </button>
              </div>
            ) : null}
            <FormField
              label={firstTimeSetup ? "New password" : "Password"}
              name="unlockPassword"
              type="password"
              autoComplete={firstTimeSetup ? "new-password" : "current-password"}
              required
              placeholder={firstTimeSetup ? "Choose a password" : "Your password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <Button type="submit" loading={unlocking} disabled={!password}>
              {firstTimeSetup ? "Set password & continue" : "Unlock"}
            </Button>
          </form>
        </div>
      </div>
    </div>
  );
}

function ThreadPlaceholder(): JSX.Element {
  return (
    <div className="conv__placeholder">
      <LatticeField variant="feature" />
      <div style={{ position: "relative", zIndex: 1, maxWidth: "42ch" }}>
        <h2 className="conv__placeholder-title">Encrypted channel idle.</h2>
        <p className="conv__placeholder-body">
          Select a conversation, or start a new one. Every message is encrypted in your
          browser with ML-KEM-768 + AES-256-GCM — the server only ever relays
          ciphertext.
        </p>
      </div>
    </div>
  );
}

interface GroupPanelProps {
  participants: ConversationParticipantResponse[];
  isAdmin: boolean;
  peerUsernameById: Record<string, string>;
  addMemberSelection: UserSummaryResponse[];
  setAddMemberSelection: (v: UserSummaryResponse[]) => void;
  addingMember: boolean;
  onAddMember: (e: React.FormEvent) => void;
  onRemoveMember: (userId: string, label: string) => void;
}

interface ActiveThreadProps {
  conversationId: string;
  messages: MessageResponse[];
  selfUserId: string;
  /** Resolved peer username, or a truncated-id fallback, or null. */
  peerLabel: string | null;
  draft: string;
  setDraft: (v: string) => void;
  onSend: (e: React.FormEvent) => void;
  onAttachFile: (e: React.ChangeEvent<HTMLInputElement>) => void;
  loadFile: (conversationId: string, message: MessageResponse) => Promise<void>;
  retryLoadFile: (conversationId: string, message: MessageResponse) => Promise<void>;
  sending: boolean;
  realtimeStatus: "disconnected" | "connecting" | "open";
  /** FR-028 (UI): show a single "you were added" notice at the top of the
   * thread instead of one decrypt-error bubble per pre-join message. */
  showJoinedNotice: boolean;
  /** Show a single "some messages can't be decrypted on this device" notice
   * (with a Re-key group recovery action) instead of one decrypt-error bubble
   * per group message whose epoch key this device doesn't hold. */
  showNoKeyNotice: boolean;
  onRekeyGroup: () => void;
  /** US3: present (non-null) only when the active conversation is a group. */
  group: GroupPanelProps | null;
}

function ActiveThread(props: ActiveThreadProps): JSX.Element {
  const {
    conversationId,
    messages,
    selfUserId,
    peerLabel,
    draft,
    setDraft,
    onSend,
    onAttachFile,
    loadFile,
    retryLoadFile,
    sending,
    realtimeStatus,
    showJoinedNotice,
    showNoKeyNotice,
    onRekeyGroup,
    group,
  } = props;
  const fileInputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  // Bump a render tick when decrypted text may have landed.
  const [, bump] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => bump((n) => n + 1), 200);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [messages.length]);

  const statusLabel = useMemo(() => {
    if (realtimeStatus === "open") return "Live · realtime";
    if (realtimeStatus === "connecting") return "Connecting…";
    return "Offline";
  }, [realtimeStatus]);

  function handleComposerKeyDown(event: React.KeyboardEvent<HTMLTextAreaElement>): void {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      event.currentTarget.form?.requestSubmit();
    }
  }

  return (
    <div className="conv__thread">
      <div className="conv__thread-head">
        <span className="conv__thread-head-label mono">{peerLabel ?? "direct"}</span>
        <span className="mono" style={{ fontSize: "0.82rem", color: "var(--ink-muted)" }}>
          {messages.length} message{messages.length === 1 ? "" : "s"}
        </span>
        <span className={`conv__live conv__live--${realtimeStatus}`}>
          <span className="conv__live-dot" aria-hidden="true" />
          {statusLabel}
        </span>
      </div>

      {group ? <GroupPanel {...group} selfUserId={selfUserId} /> : null}

      <div className="conv__scroll" ref={scrollRef}>
        {showJoinedNotice ? (
          <div className="conv__system" role="note">
            <span className="conv__system-pill">
              You were added to this group — messages from before you joined aren&apos;t
              available to you.
            </span>
          </div>
        ) : null}
        {showNoKeyNotice ? (
          <div className="conv__system" role="note">
            <span className="conv__system-pill conv__system-pill--action">
              Some earlier messages in this group can&apos;t be decrypted on this
              device (your encryption key changed).
              <button
                type="button"
                className="conv__system-action"
                onClick={onRekeyGroup}
              >
                Re-key group
              </button>
            </span>
          </div>
        ) : null}
        {messages.map((m, i) => {
          const mine = m.sender_id === selfUserId;
          const grouped = i > 0 && messages[i - 1].sender_id === m.sender_id;
          const time = new Date(m.sent_at).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          });
          if (isFileMessage(m)) {
            return (
              <div
                key={m.id}
                className={`bubble bubble--file bubble--${mine ? "mine" : "theirs"}${grouped ? " bubble--grouped" : ""}`}
              >
                <FileBubble
                  conversationId={conversationId}
                  message={m}
                  loadFile={loadFile}
                  retryLoadFile={retryLoadFile}
                />
                <span className="bubble__time mono">{time}</span>
              </div>
            );
          }
          const text = getDecryptedText(m.id);
          const err = getDecryptError(m.id);
          return (
            <div
              key={m.id}
              className={`bubble bubble--${mine ? "mine" : "theirs"}${grouped ? " bubble--grouped" : ""}`}
            >
              {text !== null ? (
                <span className="bubble__text">{text}</span>
              ) : err ? (
                <span className="bubble__text bubble__text--err">
                  Couldn&apos;t decrypt this message: {err}
                </span>
              ) : (
                <span className="bubble__loader" aria-label="Decrypting…" role="status" />
              )}
              <span className="bubble__time mono">{time}</span>
            </div>
          );
        })}
      </div>

      <form className="conv__composer" onSubmit={onSend}>
        <input
          ref={fileInputRef}
          type="file"
          accept={FILE_INPUT_ACCEPT}
          className="conv__composer-file-input"
          onChange={onAttachFile}
          aria-label="Attach a file or image"
        />
        <Button
          type="button"
          variant="ghost"
          className="conv__composer-attach"
          onClick={() => fileInputRef.current?.click()}
          disabled={sending}
          title="Attach a PDF or image (max 100 MB)"
        >
          📎
        </Button>
        <Textarea
          className="conv__composer-input"
          placeholder="Write an encrypted message… (Enter to send, Shift+Enter for a new line)"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={handleComposerKeyDown}
          aria-label="Message"
        />
        <Button type="submit" loading={sending} disabled={!draft.trim()}>
          Send
        </Button>
      </form>
    </div>
  );
}

interface FileBubbleProps {
  conversationId: string;
  message: MessageResponse;
  loadFile: (conversationId: string, message: MessageResponse) => Promise<void>;
  retryLoadFile: (conversationId: string, message: MessageResponse) => Promise<void>;
}

/** Renders one file/image share (US4): triggers the lazy download+decrypt on
 * mount (or picks up the prefetch already started on conversation open), then
 * shows an inline image or a filename/download link once `loadFile` populates
 * the in-memory `decryptedFileCache`. While loading it shows a spinner (not
 * static "Decrypting file…" text); on failure it shows a neutral Retry link
 * (never the raw error string). */
function FileBubble({
  conversationId,
  message,
  loadFile,
  retryLoadFile,
}: FileBubbleProps): JSX.Element {
  // `loadFile` mutates the module-level decryptedFileCache/fileLoadErrors maps
  // directly (not React state) and signals completion by bumping this store
  // counter — without subscribing to it here, this component has no way to
  // know decryption finished and only updates on the next unrelated re-render.
  useMessagingStore((s) => s.fileCacheVersion);

  useEffect(() => {
    void loadFile(conversationId, message);
    // Only re-run if the message or conversation identity actually changes —
    // `loadFile` itself is a stable store action reference.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conversationId, message.id]);

  const file = getDecryptedFile(message.id);
  const error = getFileLoadError(message.id);

  // Create+revoke inside the SAME effect (not create-in-useMemo +
  // revoke-in-a-separate-effect) so StrictMode's dev-only double-invoke
  // (setup -> cleanup -> setup) revokes only the URL it itself created and
  // settles on one live URL, instead of revoking the URL still held in state
  // and leaving the anchor pointing at a dead blob: reference (downloads of
  // that dead URL then fail as if the file were never fetched).
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!file) {
      setUrl(null);
      return;
    }
    const objectUrl = URL.createObjectURL(file.blob);
    setUrl(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [file]);

  if (error) {
    // Neutral, non-scary failure state: no raw error string, just a calm label
    // + a Retry link. Retry clears the cached error and re-runs the load, so a
    // transient failure (network blip during download/decrypt) recovers.
    return (
      <span className="bubble__retry">
        Couldn&apos;t load this file
        <button
          type="button"
          className="bubble__retry-button"
          onClick={() => void retryLoadFile(conversationId, message)}
        >
          Retry
        </button>
      </span>
    );
  }
  if (!file || !url) {
    return <span className="bubble__loader" aria-label="Decrypting file…" role="status" />;
  }
  if (file.contentType.startsWith("image/")) {
    return (
      <a href={url} target="_blank" rel="noreferrer" className="bubble__image-link">
        <img src={url} alt={file.filename || "shared image"} className="bubble__image" />
      </a>
    );
  }
  return (
    <a href={url} download={file.filename || "file"} className="bubble__file">
      <span className="bubble__file-icon" aria-hidden="true">
        📄
      </span>
      <span className="bubble__file-name">{file.filename || "shared file"}</span>
    </a>
  );
}

function GroupPanel(props: GroupPanelProps & { selfUserId: string }): JSX.Element {
  const {
    participants,
    isAdmin,
    peerUsernameById,
    addMemberSelection,
    setAddMemberSelection,
    addingMember,
    onAddMember,
    onRemoveMember,
    selfUserId,
  } = props;
  return (
    <div className="conv__group-panel">
      <div className="conv__group-members">
        {participants.map((p) => {
          const isSelf = p.user_id === selfUserId;
          const label = isSelf ? "you" : peerLabel(peerUsernameById, p.user_id);
          // Any member can leave themselves; an admin can also remove others.
          // Both paths go through `removeGroupMember` so a departure always
          // triggers a rekey excluding the departing member (FR-028) — unlike
          // the generic per-user-leave endpoint used for direct chats, which
          // does NOT rekey and would leave a departed group member still
          // holding the current epoch key.
          const canRemove = isSelf || (isAdmin && !isSelf);
          return (
            <span
              key={p.user_id}
              className={`conv__group-chip mono${isSelf ? " conv__group-chip--self" : ""}`}
            >
              {label}
              {p.role === "group_admin" ? " · admin" : ""}
              {canRemove ? (
                <button
                  type="button"
                  className="conv__group-chip-remove"
                  onClick={() => onRemoveMember(p.user_id, label)}
                  aria-label={
                    p.user_id === selfUserId ? "Leave this group" : `Remove ${label} from the group`
                  }
                  title={p.user_id === selfUserId ? "Leave group" : "Remove from group"}
                >
                  ×
                </button>
              ) : null}
            </span>
          );
        })}
      </div>
      {isAdmin ? (
        <form className="conv__group-add" onSubmit={onAddMember}>
          <UserPicker
            mode="single"
            label="Add member"
            placeholder="Search by username…"
            selected={addMemberSelection}
            onChange={setAddMemberSelection}
            excludeIds={participants.map((p) => p.user_id)}
            disabled={addingMember}
          />
          <Button
            type="submit"
            variant="ghost"
            loading={addingMember}
            disabled={!addMemberSelection.length}
          >
            Add
          </Button>
        </form>
      ) : null}
    </div>
  );
}