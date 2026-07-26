"""ConversationKeyBackup model — password-recoverable per-conversation message
key backup (mirrors FR-054's identity-key recovery, extended to the 1:1
conversation symmetric key).

The per-conversation AES-256-GCM message key (`conversationCrypto.ts`) is
derived once, client-side, from an ML-KEM-768 shared secret. The *recipient*
side can always re-derive it later by decapsulating the KEM ciphertext carried
in the conversation's first message. The *initiator* side cannot: their copy of
the derived key exists only in `localStorage`, generated once from a random
KEM encapsulation with no ciphertext to redo decapsulation against. Clearing
browser storage therefore permanently loses that user's access to the
conversation's history unless the key itself is backed up somewhere.

This table stores exactly that backup: the message key wrapped (encrypted)
under the same password-derived wrapping key as the user's identity keypair
(FR-054), AAD-bound to the conversation id. Opaque to the server — it stores
and relays ciphertext but never decrypts (the wrapping key is derived
client-side from the password and never sent to the backend).

One row per (conversation, user): each participant backs up their own view of
the key independently.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.core.database import Base


class ConversationKeyBackup(Base):
    __tablename__ = "conversation_key_backups"
    __table_args__ = (
        UniqueConstraint("conversation_id", "user_id", name="uq_conversation_key_backup"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Opaque to the server: AES-256-GCM(wrapKey, messageKey, AAD=conversation_id).
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrap_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrap_kdf_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrap_kdf_params: Mapped[str] = mapped_column(String(64), nullable=False)
    wrap_alg: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
