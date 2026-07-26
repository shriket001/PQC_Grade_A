"""SessionService — issues/revokes sessions and mints access tokens (FR-003/FR-004/FR-005).

Owns the mechanics of credential issuance: creating a refresh-token-backed
Session row, minting a short-lived access token over the `TokenSigner` interface,
and decoding/verifying presented access tokens. Password verification, email
verification, and orchestration live in `AuthService`, not here.

Refresh tokens are random bytes whose SHA3-256 hash (via `DigestProvider`) is
what the database stores — the raw refresh token is returned to the client once
and never persisted (FR-041 applied to refresh credentials).
"""

import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from src.core.config import Settings
from src.crypto.interfaces import DigestProvider, TokenSigner
from src.models.session import Session
from src.repositories.session_repository import SessionRepository
from src.services import access_tokens
from src.services.errors import InvalidRefreshTokenError


class SessionService:
    def __init__(
        self,
        session_repo: SessionRepository,
        token_signer: TokenSigner,
        digest_provider: DigestProvider,
        settings: Settings,
    ) -> None:
        self._session_repo = session_repo
        self._token_signer = token_signer
        self._digest = digest_provider
        self._settings = settings

    def _hash_token(self, raw: str) -> str:
        return self._digest.digest(raw.encode("utf-8")).hex()

    async def create_session(
        self, *, user_id: UUID, device_context: str | None = None
    ) -> tuple[Session, str]:
        """Persist a new session; return (session, raw_refresh_token)."""
        raw_refresh = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        session = Session(
            user_id=user_id,
            refresh_token_hash=self._hash_token(raw_refresh),
            device_context=device_context,
            created_at=now,
            expires_at=now + timedelta(seconds=self._settings.jwt_refresh_token_ttl_seconds),
        )
        await self._session_repo.add(session)
        return session, raw_refresh

    async def refresh_session(self, raw_refresh_token: str) -> tuple[Session, str]:
        """Redeem a refresh token: validate it, then rotate it in place.

        Returns (session, new_raw_refresh_token). Raises `InvalidRefreshTokenError`
        if the token is unknown, its session was revoked (e.g. by logout), or it
        has expired — a single generic error so none of those cases distinguishes
        "token exists but is dead" from "token never existed" to the caller.
        """
        session = await self._session_repo.get_by_refresh_token_hash(
            self._hash_token(raw_refresh_token)
        )
        if session is None or not session.is_active:
            raise InvalidRefreshTokenError()

        new_raw_refresh = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        await self._session_repo.rotate_refresh_token(
            session,
            new_hash=self._hash_token(new_raw_refresh),
            new_expires_at=now + timedelta(seconds=self._settings.jwt_refresh_token_ttl_seconds),
        )
        return session, new_raw_refresh

    def mint_access_token(self, *, user_id: UUID, session_id: UUID) -> str:
        return access_tokens.mint(
            self._token_signer,
            user_id=user_id,
            session_id=session_id,
            ttl_seconds=self._settings.jwt_access_token_ttl_seconds,
        )

    def decode_access_token(self, token: str) -> access_tokens.AccessTokenClaims:
        return access_tokens.decode(self._token_signer, token)

    async def revoke(self, session: Session) -> None:
        await self._session_repo.revoke(session)
