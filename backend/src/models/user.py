"""User model — account holder. Passwords are Argon2id hashes, never plaintext (FR-041)."""

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.email_verification_token import EmailVerificationToken
    from src.models.external_identity_link import ExternalIdentityLink
    from src.models.identity_key import IdentityKeyRecord
    from src.models.mfa_factor import MfaFactor
    from src.models.role import UserRole
    from src.models.session import Session


class UserStatus(enum.StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Case-insensitive uniqueness (FR-001) is enforced by normalizing to
    # lowercase at the repository layer before every write/query, plus the
    # unique index below — see data-model.md's User entity for the rationale
    # (deliberately not Postgres `citext`, to avoid an extra DB extension).
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)

    # The application's unique public handle: users start conversations and are
    # discovered by username (FR-052/FR-053). Case-insensitive uniqueness is
    # enforced by normalizing to lowercase at the service/repository layer plus
    # the unique index below — same approach as `email`.
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)

    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    # Friendly display name; defaults to the username at registration and is
    # editable later via profile management (US7/FR-015). Distinct from
    # `username`, which is the unique identifier used for discovery.
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    avatar_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status"), default=UserStatus.ACTIVE, nullable=False
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    user_roles: Mapped[list["UserRole"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    email_verification_tokens: Mapped[list["EmailVerificationToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    identity_keys: Mapped[list["IdentityKeyRecord"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    mfa_factors: Mapped[list["MfaFactor"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    external_identity_links: Mapped[list["ExternalIdentityLink"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
