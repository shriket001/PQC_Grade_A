"""SamlService — SAML Relying Party / Service Provider login (FR-011 inbound
direction).

Structurally the mirror of `OidcService`: finds-or-creates a local `User` via
the SAME `ExternalIdentityLinker` (protocol="saml" instead of "oidc") and
issues a normal local session — the exact same `(TokenResponse,
raw_refresh_token)` shape, so `api/v1/saml.py`'s ACS endpoint hands off into
the same cookie-setting helper the rest of `auth.py` uses.
"""

from datetime import UTC, datetime, timedelta

from src.core.config import Settings
from src.models.external_identity_link import ExternalIdentityProtocol
from src.models.user import UserStatus
from src.schemas.auth import TokenResponse
from src.services.audit import AuditLogger
from src.services.errors import (
    AccountDisabledError,
    SamlAssertionRejectedError,
    SamlProviderNotSupportedError,
)
from src.services.external_identity_linker import ExternalIdentityLinker
from src.services.saml_client import SamlClient, SamlExchangeError
from src.services.session_service import SessionService


class SamlService:
    def __init__(
        self,
        *,
        clients: dict[str, SamlClient],
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

    def _get_client(self, idp: str) -> SamlClient:
        client = self._clients.get(idp)
        if client is None:
            raise SamlProviderNotSupportedError(f"unknown or unconfigured SAML idp '{idp}'")
        return client

    def build_login_redirect(self, idp: str, relay_state: str) -> tuple[str, str]:
        """Returns (redirect_url, request_id) — the caller must stash
        `request_id` (e.g. in a short-lived cookie) and hand it back to
        `handle_acs` so the response can be bound to this specific request."""
        return self._get_client(idp).login_redirect(relay_state)

    def metadata_xml(self, idp: str) -> str:
        return self._get_client(idp).metadata_xml()

    async def handle_acs(
        self, idp: str, saml_response_b64: str, request_id: str
    ) -> tuple[TokenResponse, str]:
        """Returns (response body, raw refresh token) — same contract as
        `AuthService.login`/`.refresh`, for the same reason (only the router
        sets the HttpOnly cookie; this layer stays transport-agnostic)."""
        client = self._get_client(idp)
        try:
            profile = client.process_response(saml_response_b64, request_id)
        except SamlExchangeError as err:
            raise SamlAssertionRejectedError(str(err)) from err

        user = await self._linker.find_or_create_user(ExternalIdentityProtocol.SAML, profile)
        if user.status == UserStatus.DISABLED:
            await self._audit.record(
                action="saml_login",
                actor_id=user.id,
                outcome="failure",
                context={"idp": idp, "reason": "account_disabled"},
            )
            raise AccountDisabledError()

        session, raw_refresh = await self._sessions.create_session(
            user_id=user.id, device_context=f"SAML ({idp})"
        )
        access_token = self._sessions.mint_access_token(user_id=user.id, session_id=session.id)
        await self._audit.record(
            action="saml_login",
            actor_id=user.id,
            outcome="success",
            context={"idp": idp, "session_id": str(session.id)},
        )
        tokens = TokenResponse(
            access_token=access_token,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=self._settings.jwt_access_token_ttl_seconds),
        )
        return tokens, raw_refresh
