"""DI composition root.

Concrete repositories, crypto providers, services, and collaborators are
constructed here and wired into the layers that consume them via FastAPI's
`Depends` — no business layer instantiates its own dependencies (Constitution
§2.2). Story services add their own providers here as they're implemented.
"""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import Settings, get_settings
from src.core.database import get_db_session
from src.crypto.factory import (
    get_digest_provider,
    get_identity_key_provider,
    get_message_cipher,
    get_password_hasher,
    get_token_signer,
)
from src.models.session import Session
from src.models.user import User
from src.repositories.conversation_key_backup_repository import (
    ConversationKeyBackupRepository,
)
from src.repositories.conversation_repository import ConversationRepository
from src.repositories.external_identity_link_repository import ExternalIdentityLinkRepository
from src.repositories.file_attachment_repository import FileAttachmentRepository
from src.repositories.file_storage import FileStorage
from src.repositories.identity_key_repository import IdentityKeyRepository
from src.repositories.message_repository import MessageRepository
from src.repositories.mfa_factor_repository import MfaFactorRepository
from src.repositories.session_repository import SessionRepository
from src.repositories.token_repository import TokenRepository
from src.repositories.user_repository import UserRepository
from src.services import access_tokens
from src.services.audit import AuditLogger, NoOpAuditLogger
from src.services.auth_service import AuthService
from src.services.conversation_key_backup_service import ConversationKeyBackupService
from src.services.conversation_service import ConversationService
from src.services.email_service import (
    ArqVerificationEmailSender,
    VerificationEmailSender,
    get_redis_settings,
)
from src.services.errors import UnauthenticatedError
from src.services.external_identity_linker import ExternalIdentityLinker
from src.services.file_service import FileService
from src.services.identity_key_service import IdentityKeyService
from src.services.messaging_service import MessagingService
from src.services.mfa_service import MfaService
from src.services.oidc_client import GoogleOidcClient, OidcClient
from src.services.oidc_service import OidcService
from src.services.saml_client import Pysaml2SamlClient, SamlClient
from src.services.saml_service import SamlService
from src.services.session_service import SessionService
from src.services.user_service import UserService

__all__ = [
    "AuthContext",
    "get_db_session",
    "get_user_repository",
    "get_session_repository",
    "get_token_repository",
    "get_mfa_factor_repository",
    "get_mfa_service",
    "get_external_identity_link_repository",
    "get_external_identity_linker",
    "get_oidc_clients",
    "get_oidc_service",
    "get_saml_clients",
    "get_saml_service",
    "get_identity_key_repository",
    "get_conversation_repository",
    "get_message_repository",
    "get_file_attachment_repository",
    "get_file_storage",
    "get_audit_logger",
    "get_verification_email_sender",
    "get_session_service",
    "get_auth_service",
    "get_identity_key_service",
    "get_conversation_service",
    "get_conversation_key_backup_repository",
    "get_conversation_key_backup_service",
    "get_messaging_service",
    "get_file_service",
    "get_user_service",
    "get_current_user",
    "get_current_session",
]


# --- Repositories -----------------------------------------------------------


def get_user_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> UserRepository:
    return UserRepository(session)


def get_session_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> SessionRepository:
    return SessionRepository(session)


def get_token_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> TokenRepository:
    return TokenRepository(session)


def get_mfa_factor_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> MfaFactorRepository:
    return MfaFactorRepository(session)


def get_external_identity_link_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ExternalIdentityLinkRepository:
    return ExternalIdentityLinkRepository(session)


def get_identity_key_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> IdentityKeyRepository:
    return IdentityKeyRepository(session)


def get_conversation_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ConversationRepository:
    return ConversationRepository(session)


def get_message_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> MessageRepository:
    return MessageRepository(session)


def get_conversation_key_backup_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> ConversationKeyBackupRepository:
    return ConversationKeyBackupRepository(session)


def get_file_attachment_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> FileAttachmentRepository:
    return FileAttachmentRepository(session)


# --- Crypto providers (factory-wired, single swap point for a future grade) --
# AuthService receives the hasher/digest directly (see get_auth_service); no
# separate Depends provider is needed for them since no router consumes one.


def get_file_storage(settings: Annotated[Settings, Depends(get_settings)]) -> FileStorage:
    return FileStorage(
        endpoint_url=settings.object_storage_endpoint,
        bucket=settings.object_storage_bucket,
        access_key=settings.object_storage_access_key,
        secret_key=settings.object_storage_secret_key,
    )


# --- Collaborators ----------------------------------------------------------


def get_audit_logger() -> AuditLogger:
    # US11 swaps this NoOp impl for a DB-backed AuditService without touching
    # AuthService or its call sites.
    return NoOpAuditLogger()


def get_verification_email_sender() -> VerificationEmailSender:
    return ArqVerificationEmailSender(get_redis_settings())


def get_session_service(
    session_repo: Annotated[SessionRepository, Depends(get_session_repository)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SessionService:
    return SessionService(
        session_repo=session_repo,
        token_signer=get_token_signer(),
        digest_provider=get_digest_provider(),
        settings=settings,
    )


def get_mfa_service(
    mfa_repo: Annotated[MfaFactorRepository, Depends(get_mfa_factor_repository)],
    audit_logger: Annotated[AuditLogger, Depends(get_audit_logger)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> MfaService:
    return MfaService(
        mfa_repo=mfa_repo,
        message_cipher=get_message_cipher(),
        password_hasher=get_password_hasher(),
        audit_logger=audit_logger,
        settings=settings,
    )


def get_oidc_clients(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, OidcClient]:
    """Provider name -> configured `OidcClient`. A provider only appears here
    once its credentials are set — `OidcService` treats an absent key the
    same as an unknown provider name (both raise `OAuthProviderNotSupportedError`).
    A plain `Depends`-able function (not `@lru_cache`, unlike the crypto
    factory) specifically so tests can override it with a fake client without
    needing real Google credentials.
    """
    clients: dict[str, OidcClient] = {}
    if settings.oauth_google_client_id and settings.oauth_google_client_secret:
        clients["google"] = GoogleOidcClient(
            client_id=settings.oauth_google_client_id,
            client_secret=settings.oauth_google_client_secret,
            redirect_uri=settings.oauth_google_redirect_uri,
        )
    return clients


def get_external_identity_linker(
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
    link_repo: Annotated[
        ExternalIdentityLinkRepository, Depends(get_external_identity_link_repository)
    ],
) -> ExternalIdentityLinker:
    # Shared by OidcService and SamlService — same account-linking behavior
    # (match by subject, then verified email, else create) for both protocols.
    return ExternalIdentityLinker(
        user_repo=user_repo, link_repo=link_repo, password_hasher=get_password_hasher()
    )


def get_oidc_service(
    clients: Annotated[dict[str, OidcClient], Depends(get_oidc_clients)],
    linker: Annotated[ExternalIdentityLinker, Depends(get_external_identity_linker)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit_logger: Annotated[AuditLogger, Depends(get_audit_logger)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> OidcService:
    return OidcService(
        clients=clients,
        linker=linker,
        session_service=session_service,
        audit_logger=audit_logger,
        settings=settings,
    )


def get_saml_clients(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, SamlClient]:
    """IdP name -> configured `SamlClient`. Same rationale/pattern as
    `get_oidc_clients`: absent means unconfigured (`SamlProviderNotSupportedError`),
    and this is a plain `Depends`-able function (not `@lru_cache`) so tests can
    override it with a fake client — constructing the real `Pysaml2SamlClient`
    needs actual IdP metadata XML and cert files on disk.
    """
    clients: dict[str, SamlClient] = {}
    if settings.saml_idp_metadata_path and settings.saml_sp_cert_path and settings.saml_sp_key_path:
        clients[settings.saml_idp_name] = Pysaml2SamlClient(
            entity_id=settings.saml_sp_entity_id,
            acs_url=settings.saml_sp_acs_url,
            sp_cert_file=settings.saml_sp_cert_path,
            sp_key_file=settings.saml_sp_key_path,
            idp_metadata_path=settings.saml_idp_metadata_path,
            idp_entity_id=settings.saml_idp_entity_id,
            xmlsec_binary=settings.saml_xmlsec_binary_path,
        )
    return clients


def get_saml_service(
    clients: Annotated[dict[str, SamlClient], Depends(get_saml_clients)],
    linker: Annotated[ExternalIdentityLinker, Depends(get_external_identity_linker)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit_logger: Annotated[AuditLogger, Depends(get_audit_logger)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SamlService:
    return SamlService(
        clients=clients,
        linker=linker,
        session_service=session_service,
        audit_logger=audit_logger,
        settings=settings,
    )


def get_auth_service(
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
    session_repo: Annotated[SessionRepository, Depends(get_session_repository)],
    token_repo: Annotated[TokenRepository, Depends(get_token_repository)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    mfa_service: Annotated[MfaService, Depends(get_mfa_service)],
    email_sender: Annotated[VerificationEmailSender, Depends(get_verification_email_sender)],
    audit_logger: Annotated[AuditLogger, Depends(get_audit_logger)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthService:
    return AuthService(
        user_repo=user_repo,
        session_repo=session_repo,
        token_repo=token_repo,
        password_hasher=get_password_hasher(),
        digest_provider=get_digest_provider(),
        session_service=session_service,
        mfa_service=mfa_service,
        email_sender=email_sender,
        audit_logger=audit_logger,
        settings=settings,
    )


def get_identity_key_service(
    identity_key_repo: Annotated[IdentityKeyRepository, Depends(get_identity_key_repository)],
) -> IdentityKeyService:
    # The provider is factory-wired (lru_cached) — a future grade swaps the
    # concrete ML-DSA-65 impl without touching this composition.
    return IdentityKeyService(
        identity_key_repo=identity_key_repo,
        identity_key_provider=get_identity_key_provider(),
    )


def get_conversation_service(
    conversation_repo: Annotated[ConversationRepository, Depends(get_conversation_repository)],
) -> ConversationService:
    return ConversationService(conversation_repo=conversation_repo)


def get_messaging_service(
    message_repo: Annotated[MessageRepository, Depends(get_message_repository)],
    conversation_repo: Annotated[ConversationRepository, Depends(get_conversation_repository)],
    identity_key_repo: Annotated[IdentityKeyRepository, Depends(get_identity_key_repository)],
) -> MessagingService:
    return MessagingService(
        message_repo=message_repo,
        conversation_repo=conversation_repo,
        identity_key_repo=identity_key_repo,
    )


def get_file_service(
    file_repo: Annotated[FileAttachmentRepository, Depends(get_file_attachment_repository)],
    message_repo: Annotated[MessageRepository, Depends(get_message_repository)],
    conversation_repo: Annotated[ConversationRepository, Depends(get_conversation_repository)],
    identity_key_repo: Annotated[IdentityKeyRepository, Depends(get_identity_key_repository)],
    storage: Annotated[FileStorage, Depends(get_file_storage)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileService:
    return FileService(
        file_repo=file_repo,
        message_repo=message_repo,
        conversation_repo=conversation_repo,
        identity_key_repo=identity_key_repo,
        storage=storage,
        settings=settings,
    )


def get_conversation_key_backup_service(
    backup_repo: Annotated[
        ConversationKeyBackupRepository, Depends(get_conversation_key_backup_repository)
    ],
    conversation_repo: Annotated[ConversationRepository, Depends(get_conversation_repository)],
) -> ConversationKeyBackupService:
    return ConversationKeyBackupService(
        backup_repo=backup_repo, conversation_repo=conversation_repo
    )


def get_user_service(
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
) -> UserService:
    return UserService(user_repo=user_repo)


# --- Auth context (request-scoped) -----------------------------------------


@dataclass(frozen=True)
class AuthContext:
    """The authenticated principal for a request: its user and active session."""

    user: User
    session: Session


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise UnauthenticatedError("missing bearer token")
    token = header[len("Bearer ") :].strip()
    if not token:
        raise UnauthenticatedError("missing bearer token")
    return token


async def get_current_session(
    request: Request,
    user_repo: Annotated[UserRepository, Depends(get_user_repository)],
    session_repo: Annotated[SessionRepository, Depends(get_session_repository)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
) -> AuthContext:
    """Resolve and validate the Bearer access token to an active session.

    Defense in depth (Constitution §8): the signed token is verified AND the
    referenced session is confirmed still active in the database, so a logged
    out / revoked session is rejected even before its short access TTL elapses.
    The cross-instance Redis revocation cache arrives in US10/Phase 12.
    """
    token = _extract_bearer_token(request)
    try:
        claims = session_service.decode_access_token(token)
    except access_tokens.InvalidAccessTokenError as err:
        raise UnauthenticatedError(str(err)) from err

    session = await session_repo.get_by_id(claims.session_id)
    if session is None or not session.is_active:
        raise UnauthenticatedError("session not active")
    user = await user_repo.get_by_id(claims.user_id)
    if user is None:
        raise UnauthenticatedError("user not found")
    return AuthContext(user=user, session=session)


async def get_current_user(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
) -> User:
    return ctx.user
