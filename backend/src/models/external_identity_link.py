"""ExternalIdentityLink model — links a local User to an external OIDC/SAML
identity provider's subject (data-model.md, FR-010/FR-011 inbound directions).

`(protocol, provider_identifier, subject)` is unique: one external identity
maps to exactly one local User. `provider_identifier` is the IdP's issuer
(e.g. Google's `https://accounts.google.com`); `subject` is that IdP's stable
subject id for the user (Google's `sub` claim) — never the user's email,
which can change or be reused, unlike a subject id.
"""

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.core.database import Base

if TYPE_CHECKING:
    from src.models.user import User


class ExternalIdentityProtocol(enum.StrEnum):
    OIDC = "oidc"
    SAML = "saml"


class ExternalIdentityLink(Base):
    __tablename__ = "external_identity_links"
    __table_args__ = (
        UniqueConstraint(
            "protocol",
            "provider_identifier",
            "subject",
            name="uq_external_identity_links_protocol_provider_subject",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    protocol: Mapped[ExternalIdentityProtocol] = mapped_column(
        Enum(ExternalIdentityProtocol, name="external_identity_protocol", native_enum=False),
        nullable=False,
    )
    provider_identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    user: Mapped["User"] = relationship(back_populates="external_identity_links")
