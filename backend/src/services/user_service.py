"""UserService — the public user-directory surface (US2 user discovery, FR-053).

Read-only access to user profiles and username-based discovery. Authorization
(any authenticated user may look up another's public handle/keys) is enforced
by the `get_current_session` dependency on the routes; the service itself is a
pure data-access orchestrator over `UserRepository` and raises
`UserNotFoundError` for unknown ids. Never exposes email through the directory
projection — the router maps to `UserSummaryResponse` (username + display_name
only) for cross-user lookups (Constitution §8: authorization at the service
layer; FR-022: no PII leakage).
"""

from uuid import UUID

from src.models.user import User
from src.repositories.user_repository import UserRepository
from src.services.user_errors import UserNotFoundError


class UserService:
    def __init__(self, user_repo: UserRepository) -> None:
        self._user_repo = user_repo

    async def get_profile(self, user_id: UUID) -> User:
        """The self-scoped profile (incl. email + verification status)."""
        user = await self._user_repo.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError()
        return user

    async def get_summary(self, user_id: UUID) -> User:
        """A single user's public summary (router maps to UserSummaryResponse)."""
        user = await self._user_repo.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError()
        return user

    async def search_by_username(self, query: str) -> list[User]:
        """Case-insensitive username PREFIX match (FR-053), capped to a small
        result count server-side (`UserRepository._SEARCH_RESULT_CAP`) and
        rate-limited at the route layer — enough for an autocomplete/picker UX
        without becoming a bulk account-directory dump. `query` is normalized
        to lowercase here so callers can pass the raw user input."""
        return await self._user_repo.search_by_username_prefix(query.strip().lower())
