"""ExternalIdentityLinkRepository — data access for ExternalIdentityLink (FR-010/FR-011)."""

from sqlalchemy import select

from src.models.external_identity_link import ExternalIdentityLink, ExternalIdentityProtocol
from src.repositories.base import BaseRepository


class ExternalIdentityLinkRepository(BaseRepository[ExternalIdentityLink]):
    model = ExternalIdentityLink

    async def get_by_subject(
        self,
        protocol: ExternalIdentityProtocol,
        provider_identifier: str,
        subject: str,
    ) -> ExternalIdentityLink | None:
        result = await self._session.execute(
            select(ExternalIdentityLink).where(
                ExternalIdentityLink.protocol == protocol,
                ExternalIdentityLink.provider_identifier == provider_identifier,
                ExternalIdentityLink.subject == subject,
            )
        )
        return result.scalar_one_or_none()
