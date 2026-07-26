"""API tests for /auth/mfa/totp/* enroll, confirm, disable, and login step-up (FR-009)."""

import pyotp
import pytest

from tests.conftest import register_and_verify

_PASSWORD = "Sup3rSecretPass!"


async def _enroll_and_confirm(api_client, *, access_token: str) -> str:
    """Enroll + confirm MFA for the already-authenticated user; returns the secret."""
    headers = {"Authorization": f"Bearer {access_token}"}
    enroll = await api_client.client.post("/api/v1/auth/mfa/totp/enroll", headers=headers)
    assert enroll.status_code == 200, enroll.text
    secret = enroll.json()["secret"]
    assert enroll.json()["otpauth_uri"].startswith("otpauth://totp/")

    code = pyotp.TOTP(secret).now()
    confirm = await api_client.client.post(
        "/api/v1/auth/mfa/totp/confirm", json={"totp_code": code}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    assert confirm.json() == {"enabled": True}
    return secret


class TestEnrollAndConfirm:
    @pytest.mark.asyncio
    async def test_enroll_then_confirm_enables_mfa(self, api_client) -> None:
        await register_and_verify(api_client, email="ivan@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "ivan@example.com", "password": _PASSWORD}
        )
        access = login.json()["access_token"]

        await _enroll_and_confirm(api_client, access_token=access)

    @pytest.mark.asyncio
    async def test_confirm_rejects_wrong_code(self, api_client) -> None:
        await register_and_verify(api_client, email="judy@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "judy@example.com", "password": _PASSWORD}
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        await api_client.client.post("/api/v1/auth/mfa/totp/enroll", headers=headers)

        resp = await api_client.client.post(
            "/api/v1/auth/mfa/totp/confirm", json={"totp_code": "000000"}, headers=headers
        )
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_mfa_code"

    @pytest.mark.asyncio
    async def test_confirm_without_enrollment_fails(self, api_client) -> None:
        await register_and_verify(api_client, email="kevin@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "kevin@example.com", "password": _PASSWORD}
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        resp = await api_client.client.post(
            "/api/v1/auth/mfa/totp/confirm", json={"totp_code": "123456"}, headers=headers
        )
        assert resp.status_code == 400
        assert resp.json()["error_code"] == "mfa_enrollment_not_found"

    @pytest.mark.asyncio
    async def test_enroll_rejects_when_already_enabled(self, api_client) -> None:
        await register_and_verify(api_client, email="laura@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "laura@example.com", "password": _PASSWORD}
        )
        access = login.json()["access_token"]
        await _enroll_and_confirm(api_client, access_token=access)

        resp = await api_client.client.post(
            "/api/v1/auth/mfa/totp/enroll", headers={"Authorization": f"Bearer {access}"}
        )
        assert resp.status_code == 409
        assert resp.json()["error_code"] == "mfa_already_enabled"

    @pytest.mark.asyncio
    async def test_re_enrolling_before_confirm_replaces_pending_secret(self, api_client) -> None:
        await register_and_verify(api_client, email="mallory@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "mallory@example.com", "password": _PASSWORD}
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        first = await api_client.client.post("/api/v1/auth/mfa/totp/enroll", headers=headers)
        first_secret = first.json()["secret"]
        second = await api_client.client.post("/api/v1/auth/mfa/totp/enroll", headers=headers)
        second_secret = second.json()["secret"]
        assert first_secret != second_secret

        # Confirming with a code from the SUPERSEDED first secret must fail —
        # only the second (current pending) secret is live.
        stale_code = pyotp.TOTP(first_secret).now()
        resp = await api_client.client.post(
            "/api/v1/auth/mfa/totp/confirm", json={"totp_code": stale_code}, headers=headers
        )
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_mfa_code"


class TestLoginStepUp:
    @pytest.mark.asyncio
    async def test_login_without_code_is_rejected_once_mfa_enabled(self, api_client) -> None:
        await register_and_verify(api_client, email="nathan@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "nathan@example.com", "password": _PASSWORD}
        )
        await _enroll_and_confirm(api_client, access_token=login.json()["access_token"])

        resp = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "nathan@example.com", "password": _PASSWORD}
        )
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "mfa_required"

    @pytest.mark.asyncio
    async def test_login_with_correct_code_succeeds(self, api_client) -> None:
        await register_and_verify(api_client, email="olivia@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "olivia@example.com", "password": _PASSWORD}
        )
        secret = await _enroll_and_confirm(api_client, access_token=login.json()["access_token"])

        resp = await api_client.client.post(
            "/api/v1/auth/login",
            json={
                "email": "olivia@example.com",
                "password": _PASSWORD,
                "totp_code": pyotp.TOTP(secret).now(),
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["access_token"].count(".") == 2

    @pytest.mark.asyncio
    async def test_login_with_wrong_code_is_rejected(self, api_client) -> None:
        await register_and_verify(api_client, email="peter@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "peter@example.com", "password": _PASSWORD}
        )
        await _enroll_and_confirm(api_client, access_token=login.json()["access_token"])

        resp = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "peter@example.com", "password": _PASSWORD, "totp_code": "000000"},
        )
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_mfa_code"


class TestDisable:
    @pytest.mark.asyncio
    async def test_disable_with_correct_password_succeeds(self, api_client) -> None:
        await register_and_verify(api_client, email="quinn@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "quinn@example.com", "password": _PASSWORD}
        )
        access = login.json()["access_token"]
        await _enroll_and_confirm(api_client, access_token=access)

        resp = await api_client.client.request(
            "DELETE",
            "/api/v1/auth/mfa/totp",
            json={"password": _PASSWORD},
            headers={"Authorization": f"Bearer {access}"},
        )
        assert resp.status_code == 204

        # MFA is off again — a bare password login succeeds with no code.
        again = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "quinn@example.com", "password": _PASSWORD}
        )
        assert again.status_code == 200

    @pytest.mark.asyncio
    async def test_disable_with_correct_totp_code_succeeds(self, api_client) -> None:
        await register_and_verify(api_client, email="rachel@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "rachel@example.com", "password": _PASSWORD}
        )
        access = login.json()["access_token"]
        secret = await _enroll_and_confirm(api_client, access_token=access)

        resp = await api_client.client.request(
            "DELETE",
            "/api/v1/auth/mfa/totp",
            json={"totp_code": pyotp.TOTP(secret).now()},
            headers={"Authorization": f"Bearer {access}"},
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_disable_with_wrong_password_fails(self, api_client) -> None:
        await register_and_verify(api_client, email="steve@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "steve@example.com", "password": _PASSWORD}
        )
        access = login.json()["access_token"]
        await _enroll_and_confirm(api_client, access_token=access)

        resp = await api_client.client.request(
            "DELETE",
            "/api/v1/auth/mfa/totp",
            json={"password": "WrongPassword123"},
            headers={"Authorization": f"Bearer {access}"},
        )
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_credentials"

    @pytest.mark.asyncio
    async def test_disable_requires_exactly_one_proof(self, api_client) -> None:
        await register_and_verify(api_client, email="tina@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "tina@example.com", "password": _PASSWORD}
        )
        access = login.json()["access_token"]
        await _enroll_and_confirm(api_client, access_token=access)

        neither = await api_client.client.request(
            "DELETE",
            "/api/v1/auth/mfa/totp", json={}, headers={"Authorization": f"Bearer {access}"}
        )
        assert neither.status_code == 422

    @pytest.mark.asyncio
    async def test_disable_when_not_enabled_fails(self, api_client) -> None:
        await register_and_verify(api_client, email="uma@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "uma@example.com", "password": _PASSWORD}
        )
        access = login.json()["access_token"]

        resp = await api_client.client.request(
            "DELETE",
            "/api/v1/auth/mfa/totp",
            json={"password": _PASSWORD},
            headers={"Authorization": f"Bearer {access}"},
        )
        assert resp.status_code == 400
        assert resp.json()["error_code"] == "mfa_not_enabled"
