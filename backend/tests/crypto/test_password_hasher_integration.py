"""Crypto validation: stored password_hash is never plaintext, uses Argon2id via
the PasswordHasher interface, exercised through AuthService.register (T035).
"""

import pytest

from src.core.config import get_settings
from src.crypto.factory import (
    get_digest_provider,
    get_message_cipher,
    get_password_hasher,
    get_token_signer,
)
from src.repositories.mfa_factor_repository import MfaFactorRepository
from src.repositories.session_repository import SessionRepository
from src.repositories.token_repository import TokenRepository
from src.repositories.user_repository import UserRepository
from src.services.audit import NoOpAuditLogger
from src.services.auth_service import AuthService
from src.services.mfa_service import MfaService
from src.services.session_service import SessionService


class _CapturingSender:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def send(self, to_email: str, token: str) -> None:
        self.calls.append((to_email, token))


def _build_auth_service(db_session: object) -> tuple[AuthService, _CapturingSender]:
    settings = get_settings()
    user_repo = UserRepository(db_session)  # type: ignore[arg-type]
    session_repo = SessionRepository(db_session)  # type: ignore[arg-type]
    token_repo = TokenRepository(db_session)  # type: ignore[arg-type]
    session_service = SessionService(
        session_repo, get_token_signer(), get_digest_provider(), settings
    )
    mfa_repo = MfaFactorRepository(db_session)  # type: ignore[arg-type]
    mfa_service = MfaService(
        mfa_repo, get_message_cipher(), get_password_hasher(), NoOpAuditLogger(), settings
    )
    sender = _CapturingSender()
    service = AuthService(
        user_repo=user_repo,
        session_repo=session_repo,
        token_repo=token_repo,
        password_hasher=get_password_hasher(),
        digest_provider=get_digest_provider(),
        session_service=session_service,
        mfa_service=mfa_service,
        email_sender=sender,
        audit_logger=NoOpAuditLogger(),
        settings=settings,
    )
    return service, sender


class TestPasswordHasherIntegration:
    @pytest.mark.asyncio
    async def test_stored_hash_is_argon2id_not_plaintext(self, db_session: object) -> None:
        service, _ = _build_auth_service(db_session)
        password = "Sup3rSecretPass!"
        user = await service.register(
            email="crypto@example.com", password=password, username="crypto_user"
        )
        await db_session.commit()  # type: ignore[attr-defined]
        assert user.password_hash.startswith("$argon2id$")
        assert password not in user.password_hash
        assert user.email_verified is False

    @pytest.mark.asyncio
    async def test_two_users_same_password_have_distinct_hashes(self, db_session: object) -> None:
        service, _ = _build_auth_service(db_session)
        u1 = await service.register(
            email="a@example.com", password="Sup3rSecretPass!", username="user_a"
        )
        u2 = await service.register(
            email="b@example.com", password="Sup3rSecretPass!", username="user_b"
        )
        await db_session.commit()  # type: ignore[attr-defined]
        assert u1.password_hash != u2.password_hash  # per-password random salt

    @pytest.mark.asyncio
    async def test_stored_hash_verifies_through_password_hasher_interface(
        self, db_session: object
    ) -> None:
        service, _ = _build_auth_service(db_session)
        password = "Sup3rSecretPass!"
        user = await service.register(email="c@example.com", password=password, username="user_c")
        await db_session.commit()  # type: ignore[attr-defined]
        hasher = get_password_hasher()
        assert hasher.verify(password, user.password_hash) is True
        assert hasher.verify("not-the-password", user.password_hash) is False
