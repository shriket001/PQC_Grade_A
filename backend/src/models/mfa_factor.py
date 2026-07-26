"""MfaFactor model — a registered TOTP second factor (FR-009, data-model.md).

`secret_ciphertext`/`secret_nonce` hold the TOTP shared secret encrypted at
rest via the backend crypto module (`MessageCipher` + a server-held key) —
unlike a password, this secret must stay reversible to compute codes, so it's
encrypted rather than hashed. A factor is *pending* (unconfirmed) until
`enabled_at` is set by a successful `/mfa/totp/confirm`, and *active* until
`disabled_at` is set. History is kept (rows are never deleted) so past
enroll/disable events remain auditable.
"""

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, LargeBinary
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.user import User


class MfaFactorType(enum.StrEnum):
    # Grade A supports TOTP only per the confirmed spec clarification.
    TOTP = "totp"


class MfaFactor(Base):
    __tablename__ = "mfa_factors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[MfaFactorType] = mapped_column(
        Enum(MfaFactorType, name="mfa_factor_type", native_enum=False),
        nullable=False,
        default=MfaFactorType.TOTP,
    )
    secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    secret_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="mfa_factors")

    @property
    def is_pending(self) -> bool:
        return self.enabled_at is None and self.disabled_at is None

    @property
    def is_active(self) -> bool:
        return self.enabled_at is not None and self.disabled_at is None
