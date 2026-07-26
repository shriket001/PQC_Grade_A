"""MfaService — TOTP enrollment, confirmation, disablement, and login step-up (FR-009).

Owns the mechanics of the second factor: encrypting/decrypting the TOTP
secret at rest (via the injected `MessageCipher` + a server-held key — never
a concrete crypto library import, per Constitution Principle I), and
generating/verifying codes via `pyotp`. Password verification for the
disable path is delegated to the injected `PasswordHasher`; `AuthService`
composes this service for the login step-up check.
"""

from datetime import UTC, datetime
from uuid import UUID

import pyotp

from src.core.config import Settings
from src.crypto.interfaces import MessageCipher, PasswordHasher
from src.models.mfa_factor import MfaFactor
from src.models.user import User
from src.repositories.mfa_factor_repository import MfaFactorRepository
from src.services.audit import AuditLogger
from src.services.errors import (
    InvalidCredentialsError,
    InvalidMfaCodeError,
    MfaAlreadyEnabledError,
    MfaEnrollmentNotFoundError,
    MfaNotEnabledError,
    MfaRequiredError,
)

_ISSUER = "VAYUNX"
# RFC 6238 default: 30s step, +/-1 step tolerates minor clock drift between
# the server and the user's authenticator app.
_VALID_WINDOW = 1


class MfaService:
    def __init__(
        self,
        mfa_repo: MfaFactorRepository,
        message_cipher: MessageCipher,
        password_hasher: PasswordHasher,
        audit_logger: AuditLogger,
        settings: Settings,
    ) -> None:
        self._mfa_repo = mfa_repo
        self._cipher = message_cipher
        self._password_hasher = password_hasher
        self._audit = audit_logger
        self._settings = settings

    def _aad(self, user_id: UUID) -> bytes:
        # Binds ciphertext to the owning user — a row copied onto another
        # user's `user_id` (e.g. a DB restore mistake) fails to decrypt rather
        # than silently verifying against the wrong secret.
        return str(user_id).encode("utf-8")

    def _encrypt_secret(self, user_id: UUID, secret: str) -> tuple[bytes, bytes]:
        return self._cipher.encrypt(
            self._settings.mfa_secret_encryption_key_bytes,
            secret.encode("utf-8"),
            associated_data=self._aad(user_id),
        )

    def _decrypt_secret(self, factor: MfaFactor) -> str:
        plaintext = self._cipher.decrypt(
            self._settings.mfa_secret_encryption_key_bytes,
            factor.secret_ciphertext,
            factor.secret_nonce,
            associated_data=self._aad(factor.user_id),
        )
        return plaintext.decode("utf-8")

    async def enroll(self, user: User) -> tuple[str, str]:
        """Start (or restart) enrollment. Returns (otpauth_uri, secret)."""
        active = await self._mfa_repo.get_active_for_user(user.id)
        if active is not None:
            raise MfaAlreadyEnabledError()

        # A prior, never-confirmed enrollment is superseded rather than piled
        # up alongside — it never took effect, so there's nothing to preserve.
        pending = await self._mfa_repo.get_pending_for_user(user.id)
        if pending is not None:
            await self._mfa_repo.delete(pending)

        secret = pyotp.random_base32()
        ciphertext, nonce = self._encrypt_secret(user.id, secret)
        factor = MfaFactor(user_id=user.id, secret_ciphertext=ciphertext, secret_nonce=nonce)
        await self._mfa_repo.add(factor)

        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=_ISSUER)
        return uri, secret

    async def confirm(self, user: User, totp_code: str) -> None:
        pending = await self._mfa_repo.get_pending_for_user(user.id)
        if pending is None:
            raise MfaEnrollmentNotFoundError()

        secret = self._decrypt_secret(pending)
        if not pyotp.TOTP(secret).verify(totp_code, valid_window=_VALID_WINDOW):
            await self._audit.record(
                action="mfa.enroll_confirm",
                actor_id=user.id,
                outcome="failure",
                context={"reason": "invalid_code"},
            )
            raise InvalidMfaCodeError()

        pending.enabled_at = datetime.now(UTC)
        await self._mfa_repo.save(pending)
        await self._audit.record(
            action="mfa.enabled", actor_id=user.id, outcome="success", context={}
        )

    async def disable(self, user: User, *, password: str | None, totp_code: str | None) -> None:
        active = await self._mfa_repo.get_active_for_user(user.id)
        if active is None:
            raise MfaNotEnabledError()

        if password is not None:
            if not self._password_hasher.verify(password, user.password_hash):
                raise InvalidCredentialsError()
        else:
            assert totp_code is not None  # enforced by MfaDisableRequest's validator
            secret = self._decrypt_secret(active)
            if not pyotp.TOTP(secret).verify(totp_code, valid_window=_VALID_WINDOW):
                raise InvalidMfaCodeError()

        active.disabled_at = datetime.now(UTC)
        await self._mfa_repo.save(active)
        await self._audit.record(
            action="mfa.disabled", actor_id=user.id, outcome="success", context={}
        )

    async def verify_login_code(self, user: User, totp_code: str | None) -> None:
        """No-op if the account has no active factor. Otherwise requires and
        verifies `totp_code`, raising `MfaRequiredError`/`InvalidMfaCodeError`."""
        active = await self._mfa_repo.get_active_for_user(user.id)
        if active is None:
            return
        if not totp_code:
            raise MfaRequiredError()
        secret = self._decrypt_secret(active)
        if not pyotp.TOTP(secret).verify(totp_code, valid_window=_VALID_WINDOW):
            await self._audit.record(
                action="login",
                actor_id=user.id,
                outcome="failure",
                context={"reason": "invalid_mfa_code"},
            )
            raise InvalidMfaCodeError()
