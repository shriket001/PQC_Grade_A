"""Unit tests for UserRepository and the User model (Phase 3 / US1 groundwork)."""

import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from src.models.user import User, UserStatus
from src.repositories.user_repository import UserRepository


def _make_user(email: str = "alice@example.com", username: str = "alice") -> User:
    return User(
        id=uuid.uuid4(),
        email=email.lower(),
        username=username.lower(),
        password_hash="$argon2id$fake-hash-for-testing",
        display_name=username,
    )


class TestUserRepository:
    @pytest.mark.asyncio
    async def test_add_and_get_by_id(self, db_session) -> None:
        repo = UserRepository(db_session)
        user = await repo.add(_make_user())
        await db_session.commit()

        fetched = await repo.get_by_id(user.id)
        assert fetched is not None
        assert fetched.email == "alice@example.com"
        assert fetched.status == UserStatus.ACTIVE
        assert fetched.email_verified is False

    @pytest.mark.asyncio
    async def test_get_by_email_is_case_insensitive(self, db_session) -> None:
        repo = UserRepository(db_session)
        await repo.add(_make_user("Bob@Example.com".lower()))
        await db_session.commit()

        fetched = await repo.get_by_email("BOB@EXAMPLE.COM")
        assert fetched is not None
        assert fetched.email == "bob@example.com"

    @pytest.mark.asyncio
    async def test_email_uniqueness_is_enforced(self, db_session) -> None:
        repo = UserRepository(db_session)
        await repo.add(_make_user("dup@example.com"))
        await db_session.commit()

        # BaseRepository.add() flushes immediately, so the unique-constraint
        # violation surfaces here, not at a later db_session.commit().
        with pytest.raises(IntegrityError):
            await repo.add(_make_user("dup@example.com"))

    @pytest.mark.asyncio
    async def test_email_exists_returns_false_for_unknown_email(self, db_session) -> None:
        repo = UserRepository(db_session)
        assert await repo.email_exists("nobody@example.com") is False

    @pytest.mark.asyncio
    async def test_get_by_username_is_case_insensitive(self, db_session) -> None:
        repo = UserRepository(db_session)
        await repo.add(_make_user("zoe@example.com", username="zoe"))
        await db_session.commit()

        fetched = await repo.get_by_username("ZOE")
        assert fetched is not None
        assert fetched.username == "zoe"

    @pytest.mark.asyncio
    async def test_username_uniqueness_is_enforced(self, db_session) -> None:
        repo = UserRepository(db_session)
        await repo.add(_make_user("first@example.com", username="handle"))
        await db_session.commit()
        with pytest.raises(IntegrityError):
            await repo.add(_make_user("second@example.com", username="handle"))

    @pytest.mark.asyncio
    async def test_search_by_username_prefix_matches_and_orders_alphabetically(
        self, db_session
    ) -> None:
        repo = UserRepository(db_session)
        await repo.add(_make_user("ned@example.com", username="ned"))
        await repo.add(_make_user("nedra@example.com", username="nedra"))
        await repo.add(_make_user("nedward@example.com", username="nedward"))
        await repo.add(_make_user("other@example.com", username="somebodyelse"))
        await db_session.commit()

        matches = await repo.search_by_username_prefix("ned")
        assert [u.username for u in matches] == ["ned", "nedra", "nedward"]
        assert await repo.search_by_username_prefix("nobody") == []

    @pytest.mark.asyncio
    async def test_search_by_username_prefix_caps_results(self, db_session) -> None:
        repo = UserRepository(db_session)
        for i in range(12):
            await repo.add(_make_user(f"bulk{i}@example.com", username=f"bulk_user_{i:02d}"))
        await db_session.commit()

        matches = await repo.search_by_username_prefix("bulk_user_")
        assert len(matches) == 8  # _SEARCH_RESULT_CAP

    @pytest.mark.asyncio
    async def test_search_by_username_prefix_escapes_literal_underscore(self, db_session) -> None:
        # `_` is both a valid username character and a SQL LIKE wildcard
        # (single-char match) — it must be escaped so a literal underscore in
        # the query doesn't accidentally match unrelated usernames.
        repo = UserRepository(db_session)
        await repo.add(_make_user("a@example.com", username="ab_cd"))
        await repo.add(_make_user("b@example.com", username="abxcd"))  # would match unescaped
        await db_session.commit()

        matches = await repo.search_by_username_prefix("ab_")
        assert [u.username for u in matches] == ["ab_cd"]
