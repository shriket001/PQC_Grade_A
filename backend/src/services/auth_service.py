"""AuthService — register / verify-email / login / logout orchestration (US1).

Composes repositories, the `PasswordHasher`/`DigestProvider` crypto interfaces,
`SessionService`, a `VerificationEmailSender`, and a `AuditLogger` — all injected
(DIP). Never imports a concrete crypto library. Owns the security posture of
the auth flows: case-insensitive email, password-policy enforcement, login
enumeration defense, and the audit hook (T047) that US11 will make persistent.
"""

import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from src.core.config import Settings
from src.crypto.interfaces import DigestProvider, PasswordHasher
from src.models.email_verification_token import EmailVerificationToken
from src.models.session import Session
from src.models.user import User, UserStatus
from src.repositories.session_repository import SessionRepository
from src.repositories.token_repository import TokenRepository
from src.repositories.user_repository import UserRepository
from src.schemas.auth import TokenResponse
from src.services import password_policy
from src.services.audit import AuditLogger
from src.services.email_service import VerificationEmailSender
from src.services.errors import (
    AccountDisabledError,
    EmailAlreadyRegisteredError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidVerificationTokenError,
    SessionNotFoundError,
    UsernameAlreadyRegisteredError,
    WeakPasswordError,
)
from src.services.mfa_service import MfaService
from src.services.session_service import SessionService


class AuthService:
    # Class-level cache for the timing-equalizer dummy hash so a nonexistent
    # user still pays an Argon2 verify cost; computed once through the injected
    # hasher (DIP — no factory reach-in), shared across request instances.
    _dummy_hash: str | None = None

    def __init__(
        self,
        user_repo: UserRepository,
        session_repo: SessionRepository,
        token_repo: TokenRepository,
        password_hasher: PasswordHasher,
        digest_provider: DigestProvider,
        session_service: SessionService,
        mfa_service: MfaService,
        email_sender: VerificationEmailSender,
        audit_logger: AuditLogger,
        settings: Settings,
    ) -> None:
        self._user_repo = user_repo
        self._session_repo = session_repo
        self._token_repo = token_repo
        self._password_hasher = password_hasher
        self._digest = digest_provider
        self._sessions = session_service
        self._mfa = mfa_service
        self._email_sender = email_sender
        self._audit = audit_logger
        self._settings = settings

    def _hash_token(self, raw: str) -> str:
        return self._digest.digest(raw.encode("utf-8")).hex()

    async def _verify_or_equalize(self, user: User | None, password: str) -> bool:
        """Verify the password, or run a dummy verify when the user is absent.

        Running Argon2 even for an unknown email keeps the failed-login path
        timing-close to the real verify, so a wrong-password 401 and a
        no-such-user 401 are indistinguishable (login enumeration defense).
        """
        if user is None:
            if AuthService._dummy_hash is None:
                AuthService._dummy_hash = self._password_hasher.hash("timing-equalizer-constant")
            self._password_hasher.verify(password, AuthService._dummy_hash)
            return False
        return self._password_hasher.verify(password, user.password_hash)

    async def register(self, *, email: str, password: str, username: str) -> User:
        normalized_email = email.lower()
        normalized_username = username.lower()
        if await self._user_repo.email_exists(normalized_email):
            raise EmailAlreadyRegisteredError()
        if await self._user_repo.username_exists(normalized_username):
            raise UsernameAlreadyRegisteredError()
        try:
            password_policy.validate(password)
        except password_policy.PasswordPolicyError as err:
            raise WeakPasswordError(str(err)) from err

        user = User(
            email=normalized_email,
            username=normalized_username,
            password_hash=self._password_hasher.hash(password),
            # No separate display name is collected at registration (the signup
            # form is email + username + password); default the friendly display
            # name to the username. US7/FR-015 makes it independently editable.
            display_name=normalized_username,
        )
        await self._user_repo.add(user)

        raw_token, token_hash = self._mint_verification_token(user.id)
        await self._token_repo.add(
            EmailVerificationToken(
                user_id=user.id,
                token_hash=token_hash,
                expires_at=datetime.now(UTC)
                + timedelta(seconds=self._settings.email_verification_token_ttl_seconds),
            )
        )
        await self._email_sender.send(normalized_email, raw_token)
        await self._audit.record(
            action="register",
            actor_id=user.id,
            outcome="success",
            context={"email": normalized_email, "username": normalized_username},
        )
        return user

    def _mint_verification_token(self, user_id: UUID) -> tuple[str, str]:
        raw = secrets.token_urlsafe(32)
        return raw, self._hash_token(raw)

    async def verify_email(self, token: str) -> bool:
        record = await self._token_repo.get_by_token_hash(self._hash_token(token))
        if record is None or not record.is_valid:
            raise InvalidVerificationTokenError()
        user = await self._user_repo.get_by_id(record.user_id)
        if user is None:
            raise InvalidVerificationTokenError()
        user.email_verified = True
        record.used_at = datetime.now(UTC)
        await self._audit.record(
            action="email_verified",
            actor_id=user.id,
            outcome="success",
            context={},
        )
        return True

    async def login(
        self,
        *,
        email: str,
        password: str,
        device_context: str | None,
        totp_code: str | None = None,
    ) -> tuple[TokenResponse, str]:
        """Returns (response body, raw refresh token).

        The raw refresh token is handed back separately — never embedded in
        `TokenResponse` — so only the router (which owns the HTTP response)
        can set it as an HttpOnly cookie; the service layer stays transport-
        agnostic (FR-005/US10).
        """
        user = await self._user_repo.get_by_email(email.lower())
        authenticated = await self._verify_or_equalize(user, password)
        if user is None or not authenticated:
            await self._audit.record(
                action="login",
                actor_id=user.id if user else None,
                outcome="failure",
                context={"reason": "invalid_credentials"},
            )
            raise InvalidCredentialsError()
        if user.status == UserStatus.DISABLED:
            await self._audit.record(
                action="login",
                actor_id=user.id,
                outcome="failure",
                context={"reason": "account_disabled"},
            )
            raise AccountDisabledError()
        if not user.email_verified:
            await self._audit.record(
                action="login",
                actor_id=user.id,
                outcome="failure",
                context={"reason": "email_not_verified"},
            )
            raise EmailNotVerifiedError()

        # FR-009: no-ops if the account has no active TOTP factor; otherwise
        # raises MfaRequiredError (no/blank code) or InvalidMfaCodeError (wrong
        # code) — either way, no session is created below (password alone is
        # never sufficient once MFA is enabled).
        await self._mfa.verify_login_code(user, totp_code)

        session, raw_refresh = await self._sessions.create_session(
            user_id=user.id, device_context=device_context
        )
        access_token = self._sessions.mint_access_token(user_id=user.id, session_id=session.id)
        await self._audit.record(
            action="login",
            actor_id=user.id,
            outcome="success",
            context={"session_id": str(session.id)},
        )
        tokens = TokenResponse(
            access_token=access_token,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=self._settings.jwt_access_token_ttl_seconds),
        )
        return tokens, raw_refresh

    async def refresh(self, *, refresh_token: str) -> tuple[TokenResponse, str]:
        """Returns (response body, new raw refresh token) — see `login` above."""
        session, new_raw_refresh = await self._sessions.refresh_session(refresh_token)
        user = await self._user_repo.get_by_id(session.user_id)
        if user is None or user.status == UserStatus.DISABLED:
            # The session's refresh token was already rotated above (so a
            # replayed old token is dead either way); revoke the session
            # outright too, matching logout, since the account backing it is
            # gone or disabled and no further refresh should succeed.
            await self._sessions.revoke(session)
            await self._audit.record(
                action="refresh",
                actor_id=session.user_id,
                outcome="failure",
                context={"reason": "account_disabled" if user else "user_not_found"},
            )
            raise AccountDisabledError()

        access_token = self._sessions.mint_access_token(user_id=user.id, session_id=session.id)
        await self._audit.record(
            action="refresh",
            actor_id=user.id,
            outcome="success",
            context={"session_id": str(session.id)},
        )
        tokens = TokenResponse(
            access_token=access_token,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=self._settings.jwt_access_token_ttl_seconds),
        )
        return tokens, new_raw_refresh

    async def logout(self, session: Session) -> None:
        await self._sessions.revoke(session)
        await self._audit.record(
            action="logout",
            actor_id=session.user_id,
            outcome="success",
            context={"session_id": str(session.id)},
        )

    async def list_sessions(self, user_id: UUID) -> list[Session]:
        """Active (non-revoked, non-expired) sessions/devices for the user (FR-006)."""
        return await self._session_repo.list_active_for_user(user_id)

    async def revoke_session(self, *, user_id: UUID, session_id: UUID) -> None:
        """Revoke one of the caller's own sessions/devices by id (FR-006).

        Raises `SessionNotFoundError` (404) uniformly whether the id doesn't
        exist, belongs to a different user, or is already revoked/expired —
        no need to distinguish those cases for the caller (FR-022).
        """
        session = await self._session_repo.get_by_id(session_id)
        if session is None or session.user_id != user_id or not session.is_active:
            raise SessionNotFoundError()
        await self._sessions.revoke(session)
        await self._audit.record(
            action="session_revoked",
            actor_id=user_id,
            outcome="success",
            context={"session_id": str(session_id)},
        )
