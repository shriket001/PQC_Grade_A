"""OidcService — OIDC Relying Party login (FR-010 inbound direction).

Finds-or-creates a local `User` for a verified external identity and issues a
normal local session — the exact same `(TokenResponse, raw_refresh_token)`
shape `AuthService.login`/`.refresh` return, so `api/v1/oidc.py`'s callback
hands off into the same cookie-setting helper the rest of `auth.py` uses.

Account-linking itself (match-by-subject, then by-verified-email, else
create) is NOT implemented here — it's shared with `SamlService` via
`ExternalIdentityLinker` (see that module for the full rule), so both
protocols behave identically and a fix to one applies to both.
"""

from datetime import UTC, datetime, timedelta

from src.core.config import Settings
from src.models.external_identity_link import ExternalIdentityProtocol
from src.models.user import UserStatus
from src.schemas.auth import TokenResponse
from src.services.audit import AuditLogger
from src.services.errors import (
    AccountDisabledError,
    OAuthExchangeFailedError,
    OAuthProviderNotSupportedError,
)
from src.services.external_identity_linker import ExternalIdentityLinker
from src.services.oidc_client import OidcClient, OidcExchangeError
from src.services.session_service import SessionService


class OidcService:
    def __init__(
        self,
        *,
        clients: dict[str, OidcClient],
        linker: ExternalIdentityLinker,
        session_service: SessionService,
        audit_logger: AuditLogger,
        settings: Settings,
    ) -> None:
        self._clients = clients
        self._linker = linker
        self._sessions = session_service
        self._audit = audit_logger
        self._settings = settings

    def _get_client(self, provider: str) -> OidcClient:
        client = self._clients.get(provider)
        if client is None:
            raise OAuthProviderNotSupportedError(
                f"unknown or unconfigured OIDC provider '{provider}'"
            )
        return client

    def build_authorization_url(self, provider: str, state: str) -> str:
        return self._get_client(provider).authorization_url(state)

    async def handle_callback(self, provider: str, code: str) -> tuple[TokenResponse, str]:
        """Returns (response body, raw refresh token) — same contract as
        `AuthService.login`/`.refresh`, for the same reason (only the router
        sets the HttpOnly cookie; this layer stays transport-agnostic)."""
        client = self._get_client(provider)
        try:
            profile = await client.exchange_code(code)
        except OidcExchangeError as err:
            raise OAuthExchangeFailedError(str(err)) from err

        user = await self._linker.find_or_create_user(ExternalIdentityProtocol.OIDC, profile)
        if user.status == UserStatus.DISABLED:
            await self._audit.record(
                action="oauth_login",
                actor_id=user.id,
                outcome="failure",
                context={"provider": provider, "reason": "account_disabled"},
            )
            raise AccountDisabledError()

        session, raw_refresh = await self._sessions.create_session(
            user_id=user.id, device_context=f"OAuth ({provider})"
        )
        access_token = self._sessions.mint_access_token(user_id=user.id, session_id=session.id)
        await self._audit.record(
            action="oauth_login",
            actor_id=user.id,
            outcome="success",
            context={"provider": provider, "session_id": str(session.id)},
        )
        tokens = TokenResponse(
            access_token=access_token,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=self._settings.jwt_access_token_ttl_seconds),
        )
        return tokens, raw_refresh
