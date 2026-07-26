"""UserRepository — domain-meaningful data access for User (Constitution Principle V)."""

from sqlalchemy import select

from src.models.user import User
from src.repositories.base import BaseRepository

_SEARCH_RESULT_CAP = 8


class UserRepository(BaseRepository[User]):
    model = User

    async def get_by_email(self, email: str) -> User | None:
        """Email uniqueness is case-insensitive; callers must pass an already-lowercased
        email (normalization happens once, at the service layer, per data-model.md)."""
        result = await self._session.execute(select(User).where(User.email == email.lower()))
        return result.scalar_one_or_none()

    async def email_exists(self, email: str) -> bool:
        return await self.get_by_email(email) is not None

    async def get_by_username(self, username: str) -> User | None:
        """Username uniqueness is case-insensitive; callers must pass an
        already-lowercased username (normalized once, at the service/schema
        layer). Returns the active user with that handle, or None."""
        result = await self._session.execute(select(User).where(User.username == username.lower()))
        return result.scalar_one_or_none()

    async def username_exists(self, username: str) -> bool:
        return await self.get_by_username(username) is not None

    async def search_by_username_prefix(self, query: str) -> list[User]:
        """Case-insensitive username PREFIX match (FR-053), capped to
        `_SEARCH_RESULT_CAP` results, ordered alphabetically. Callers must pass
        an already-lowercased, non-empty query.

        The username alphabet (`^[a-zA-Z0-9_]{3,32}$`) includes `_`, which is
        also a single-character SQL `LIKE` wildcard — the query is escaped
        (`%`, `_`, and the escape character itself) before being turned into a
        `prefix%` pattern so a literal underscore in someone's search never
        accidentally matches unrelated usernames.
        """
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        result = await self._session.execute(
            select(User)
            .where(User.username.ilike(f"{escaped}%", escape="\\"))
            .order_by(User.username)
            .limit(_SEARCH_RESULT_CAP)
        )
        return list(result.scalars().all())
