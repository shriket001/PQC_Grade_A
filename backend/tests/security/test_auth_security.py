"""Security tests for the auth flows (T034):

- login failure does not reveal account existence
- unverified accounts cannot log in
- disabled accounts cannot log in
- rate limiting engages on repeated failed logins (FR-014)
"""

import pytest

from src.core.config import get_settings
from src.models.user import UserStatus
from src.repositories.user_repository import UserRepository
from tests.conftest import register_and_verify

_PASSWORD = "Sup3rSecretPass!"


class TestLoginDoesNotRevealAccountExistence:
    @pytest.mark.asyncio
    async def test_wrong_password_and_unknown_user_return_identical_failure(
        self, api_client
    ) -> None:
        await register_and_verify(api_client, email="real@example.com", password=_PASSWORD)

        wrong_password = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "real@example.com", "password": "WrongPassword123"},
        )
        unknown_user = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@example.com", "password": "WrongPassword123"},
        )

        assert wrong_password.status_code == 401
        assert unknown_user.status_code == 401
        # Same error code and message — no signal that one email exists and the
        # other does not.
        assert wrong_password.json() == unknown_user.json()
        assert wrong_password.json()["error_code"] == "invalid_credentials"


class TestUnverifiedAccountCannotLogin:
    @pytest.mark.asyncio
    async def test_unverified_login_denied_without_tokens(self, api_client) -> None:
        await api_client.client.post(
            "/api/v1/auth/register",
            json={
                "email": "unverified@example.com",
                "password": _PASSWORD,
                "username": "unverified",
            },
        )
        resp = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "unverified@example.com", "password": _PASSWORD},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["error_code"] == "email_not_verified"
        assert "access_token" not in body


class TestDisabledAccountCannotLogin:
    @pytest.mark.asyncio
    async def test_disabled_account_rejected(self, api_client, db_session) -> None:
        await register_and_verify(api_client, email="disabled@example.com", password=_PASSWORD)

        # Disable the user directly at the DB (no admin endpoint exists yet).
        repo = UserRepository(db_session)
        user = await repo.get_by_email("disabled@example.com")
        assert user is not None
        user.status = UserStatus.DISABLED
        await db_session.commit()

        resp = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "disabled@example.com", "password": _PASSWORD},
        )
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "account_disabled"


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_repeated_failed_logins_are_rate_limited(self, api_client) -> None:
        limit = get_settings().rate_limit_login_per_minute
        statuses: list[int] = []
        for _ in range(limit + 1):
            resp = await api_client.client.post(
                "/api/v1/auth/login",
                json={"email": "ghost@example.com", "password": "WrongPassword123"},
            )
            statuses.append(resp.status_code)

        # The first `limit` attempts are denied as invalid credentials; the next
        # one is blocked by the rate limiter (FR-014).
        assert statuses[:limit] == [401] * limit
        assert statuses[limit] == 429
        # Confirm via a fresh request that the body carries the rate-limit code.
        over = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@example.com", "password": "WrongPassword123"},
        )
        assert over.status_code == 429
        assert over.json()["error_code"] == "rate_limited"
