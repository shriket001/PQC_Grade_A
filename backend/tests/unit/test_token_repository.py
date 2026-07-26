"""Unit tests for TokenRepository / EmailVerificationToken (FR-002)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from src.models.email_verification_token import EmailVerificationToken
from src.models.user import User
from src.repositories.token_repository import TokenRepository
from src.repositories.user_repository import UserRepository


async def _make_persisted_user(db_session) -> User:
    user = User(
        id=uuid.uuid4(),
        email="dave@example.com",
        username="dave",
        password_hash="$argon2id$fake-hash-for-testing",
        display_name="Dave",
    )
    await UserRepository(db_session).add(user)
    await db_session.commit()
    return user


class TestTokenRepository:
    @pytest.mark.asyncio
    async def test_get_by_token_hash(self, db_session) -> None:
        user = await _make_persisted_user(db_session)
        repo = TokenRepository(db_session)
        token = await repo.add(
            EmailVerificationToken(
                id=uuid.uuid4(),
                user_id=user.id,
                token_hash="a-token-hash",
                expires_at=datetime.now(UTC) + timedelta(hours=24),
            )
        )
        await db_session.commit()

        fetched = await repo.get_by_token_hash("a-token-hash")
        assert fetched is not None
        assert fetched.id == token.id
        assert fetched.is_valid is True

    @pytest.mark.asyncio
    async def test_expired_token_is_not_valid(self, db_session) -> None:
        user = await _make_persisted_user(db_session)
        repo = TokenRepository(db_session)
        token = await repo.add(
            EmailVerificationToken(
                id=uuid.uuid4(),
                user_id=user.id,
                token_hash="expired-hash",
                expires_at=datetime.now(UTC) - timedelta(hours=1),
            )
        )
        await db_session.commit()

        assert token.is_valid is False

    @pytest.mark.asyncio
    async def test_used_token_is_not_valid(self, db_session) -> None:
        user = await _make_persisted_user(db_session)
        repo = TokenRepository(db_session)
        token = await repo.add(
            EmailVerificationToken(
                id=uuid.uuid4(),
                user_id=user.id,
                token_hash="used-hash",
                expires_at=datetime.now(UTC) + timedelta(hours=24),
                used_at=datetime.now(UTC),
            )
        )
        await db_session.commit()

        assert token.is_valid is False
