"""TokenRepository — domain-meaningful data access for EmailVerificationToken (FR-002).

US7 (Phase 9) adds a sibling repository for `PasswordResetToken` once that
model exists — this class is scoped to email verification only for now,
matching what Phase 3 actually creates.
"""

from sqlalchemy import select

from src.models.email_verification_token import EmailVerificationToken
from src.repositories.base import BaseRepository


class TokenRepository(BaseRepository[EmailVerificationToken]):
    model = EmailVerificationToken

    async def get_by_token_hash(self, token_hash: str) -> EmailVerificationToken | None:
        result = await self._session.execute(
            select(EmailVerificationToken).where(EmailVerificationToken.token_hash == token_hash)
        )
        return result.scalar_one_or_none()
