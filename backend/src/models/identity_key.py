"""IdentityKeyRecord model — server-side public-key directory entry (US2).

The server stores **public key material only**; the corresponding private keys
never leave the client in plaintext (research.md #1, spec FR-043/FR-044). A user
may hold multiple records (one per device, distinguished by `device_label`).
Rotation (FR-049) creates a new record with an incremented `key_version` and
marks the prior record `superseded_at` (retained, not deleted, so old messages
remain verifiable).

FR-054 (cross-device recovery): optionally, the client may store the private
keypair **wrapped** (encrypted) under a password-derived key so the same
identity can be recovered on a new device. The wrapped blobs + wrap parameters
below are opaque to the server — it stores and relays them but never decrypts
(plaintext + the wrapping key live only in the browser). All wrap_* columns are
nullable: legacy rows and the public directory view carry none.
"""

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.message import Message
    from src.models.user import User


class IdentityKeyRecord(Base):
    __tablename__ = "identity_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_label: Mapped[str] = mapped_column(String(100), nullable=False)
    # ML-DSA-65 public signing key — authorship verification (FR-043).
    public_signing_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # ML-KEM-768 public key-exchange key (FR-044).
    public_kem_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Signature by the outgoing key over the new key, present iff this record
    # supersedes a prior one (FR-049).
    rotation_attestation: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # ---- FR-054: password-wrapped private keypair (opaque to the server) ----
    # All nullable; present iff the client opted into cross-device recovery.
    # Wrapped with AES-256-GCM under a key derived from the user's
    # password (Argon2id -> HKDF-SHA3-256). AAD = the matching public key.
    wrapped_signing_private_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    wrapped_kem_private_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    wrap_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    wrap_kdf_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # e.g. "argon2id:t=3:m=65536:p=4" — stored so any device can reproduce the KDF.
    wrap_kdf_params: Mapped[str | None] = mapped_column(String(64), nullable=True)
    wrap_alg: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="identity_keys")
    messages: Mapped[list["Message"]] = relationship(back_populates="sender_identity_key")


# Exposed as an enum so future key purposes (e.g. one-time prekeys) can extend
# without a schema change; currently only signing + KEM are modelled.
class IdentityKeyPurpose(enum.StrEnum):
    """Marker for which key material a record carries (documentation-only for now)."""

    SIGNING = "signing"
    KEY_EXCHANGE = "key_exchange"
