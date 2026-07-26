"""Unit tests for SessionRepository (FR-006, FR-007)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from src.models.session import Session
from src.models.user import User
from src.repositories.session_repository import SessionRepository
from src.repositories.user_repository import UserRepository


async def _make_persisted_user(db_session) -> User:
    user = User(
        id=uuid.uuid4(),
        email="carol@example.com",
        username="carol",
        password_hash="$argon2id$fake-hash-for-testing",
        display_name="Carol",
    )
    await UserRepository(db_session).add(user)
    await db_session.commit()
    return user


def _make_session(user_id: uuid.UUID, *, revoked: bool = False) -> Session:
    now = datetime.now(UTC)
    return Session(
        id=uuid.uuid4(),
        user_id=user_id,
        refresh_token_hash=f"hash-{uuid.uuid4()}",
        expires_at=now + timedelta(days=30),
        revoked_at=now if revoked else None,
    )


class TestSessionRepository:
    @pytest.mark.asyncio
    async def test_get_by_refresh_token_hash(self, db_session) -> None:
        user = await _make_persisted_user(db_session)
        repo = SessionRepository(db_session)
        session = await repo.add(_make_session(user.id))
        await db_session.commit()

        fetched = await repo.get_by_refresh_token_hash(session.refresh_token_hash)
        assert fetched is not None
        assert fetched.id == session.id
        assert fetched.is_active is True

    @pytest.mark.asyncio
    async def test_list_active_for_user_excludes_revoked(self, db_session) -> None:
        user = await _make_persisted_user(db_session)
        repo = SessionRepository(db_session)
        await repo.add(_make_session(user.id))
        await repo.add(_make_session(user.id, revoked=True))
        await db_session.commit()

        active = await repo.list_active_for_user(user.id)
        assert len(active) == 1
        assert active[0].revoked_at is None

    @pytest.mark.asyncio
    async def test_revoke_all_for_user(self, db_session) -> None:
        user = await _make_persisted_user(db_session)
        repo = SessionRepository(db_session)
        await repo.add(_make_session(user.id))
        await repo.add(_make_session(user.id))
        await db_session.commit()

        await repo.revoke_all_for_user(user.id)
        await db_session.commit()

        assert await repo.list_active_for_user(user.id) == []
