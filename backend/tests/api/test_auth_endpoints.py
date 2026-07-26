"""API tests for /auth/register, /auth/verify-email, /auth/login, /auth/logout (T033)."""

import pytest

from tests.conftest import register_and_verify

_PASSWORD = "Sup3rSecretPass!"


class TestRegister:
    @pytest.mark.asyncio
    async def test_register_creates_unverified_account_and_enqueues_email(self, api_client) -> None:
        resp = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "alice@example.com", "password": _PASSWORD, "username": "alice"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "unverified"
        assert body["username"] == "alice"
        assert "user_id" in body
        assert len(api_client.emails.calls) == 1
        assert api_client.emails.calls[0][0] == "alice@example.com"
        assert api_client.emails.calls[0][1]  # non-empty token

    @pytest.mark.asyncio
    async def test_register_normalizes_username_to_lowercase(self, api_client) -> None:
        resp = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "case@example.com", "password": _PASSWORD, "username": "Casey"},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["username"] == "casey"  # stored canonical lowercase

    @pytest.mark.asyncio
    async def test_register_rejects_duplicate_email(self, api_client) -> None:
        payload = {"email": "dup@example.com", "password": _PASSWORD, "username": "dup"}
        first = await api_client.client.post("/api/v1/auth/register", json=payload)
        assert first.status_code == 201
        second = await api_client.client.post("/api/v1/auth/register", json=payload)
        assert second.status_code == 409
        assert second.json()["error_code"] == "email_already_registered"

    @pytest.mark.asyncio
    async def test_register_rejects_duplicate_username(self, api_client) -> None:
        first = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "u1@example.com", "password": _PASSWORD, "username": "taken"},
        )
        assert first.status_code == 201
        # Same username, different email — the handle is the unique identifier.
        second = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "u2@example.com", "password": _PASSWORD, "username": "taken"},
        )
        assert second.status_code == 409
        assert second.json()["error_code"] == "username_taken"

    @pytest.mark.asyncio
    async def test_register_rejects_duplicate_username_case_insensitively(self, api_client) -> None:
        first = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "c1@example.com", "password": _PASSWORD, "username": "handle"},
        )
        assert first.status_code == 201
        second = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "c2@example.com", "password": _PASSWORD, "username": "HANDLE"},
        )
        assert second.status_code == 409
        assert second.json()["error_code"] == "username_taken"

    @pytest.mark.asyncio
    async def test_register_rejects_weak_password(self, api_client) -> None:
        resp = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "weak@example.com", "password": "short", "username": "weak"},
        )
        assert resp.status_code == 400
        assert resp.json()["error_code"] == "weak_password"

    @pytest.mark.asyncio
    async def test_register_rejects_invalid_email(self, api_client) -> None:
        resp = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "not-an-email", "password": _PASSWORD, "username": "bad"},
        )
        assert resp.status_code == 422  # DTO validation, before the service layer

    @pytest.mark.asyncio
    async def test_register_rejects_invalid_username_format(self, api_client) -> None:
        # Too short and disallowed characters — DTO pattern validation (422).
        resp = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "fmt@example.com", "password": _PASSWORD, "username": "a b!"},
        )
        assert resp.status_code == 422


class TestVerifyEmail:
    @pytest.mark.asyncio
    async def test_verify_email_succeeds_with_emitted_token(self, api_client) -> None:
        await register_and_verify(api_client, email="bob@example.com", password=_PASSWORD)
        # register_and_verify already asserted 200; sanity-check the capture
        assert api_client.emails.calls

    @pytest.mark.asyncio
    async def test_verify_email_rejects_bogus_token(self, api_client) -> None:
        resp = await api_client.client.post(
            "/api/v1/auth/verify-email", json={"verification_token": "totally-bogus-token"}
        )
        assert resp.status_code == 400
        assert resp.json()["error_code"] == "invalid_verification_token"

    @pytest.mark.asyncio
    async def test_verify_email_token_is_single_use(self, api_client) -> None:
        resp = await api_client.client.post(
            "/api/v1/auth/register",
            json={"email": "once@example.com", "password": _PASSWORD, "username": "once"},
        )
        assert resp.status_code == 201
        token = api_client.emails.calls[-1][1]
        first = await api_client.client.post(
            "/api/v1/auth/verify-email", json={"verification_token": token}
        )
        assert first.status_code == 200
        second = await api_client.client.post(
            "/api/v1/auth/verify-email", json={"verification_token": token}
        )
        assert second.status_code == 400
        assert second.json()["error_code"] == "invalid_verification_token"


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_requires_email_verification(self, api_client) -> None:
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
        assert resp.json()["error_code"] == "email_not_verified"

    @pytest.mark.asyncio
    async def test_login_succeeds_after_verification(self, api_client) -> None:
        await register_and_verify(api_client, email="carol@example.com", password=_PASSWORD)
        resp = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "carol@example.com", "password": _PASSWORD, "device_context": "web"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["access_token"].count(".") == 2  # compact JWS: header.payload.sig
        assert "refresh_token" not in body  # never in the body — HttpOnly cookie only
        assert resp.cookies.get("vayunx_refresh_token")
        assert body["expires_at"]

    @pytest.mark.asyncio
    async def test_login_rejects_wrong_password(self, api_client) -> None:
        await register_and_verify(api_client, email="dave@example.com", password=_PASSWORD)
        resp = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "dave@example.com", "password": "WrongPassword123"},
        )
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_credentials"


class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_revokes_session(self, api_client) -> None:
        await register_and_verify(api_client, email="erin@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "erin@example.com", "password": _PASSWORD},
        )
        assert login.status_code == 200
        access = login.json()["access_token"]

        logout = await api_client.client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"}
        )
        assert logout.status_code == 204

        # The session is revoked; the same access token is now rejected even
        # though its signature/expiry are still valid (defense in depth).
        again = await api_client.client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"}
        )
        assert again.status_code == 401
        assert again.json()["error_code"] == "unauthenticated"

    @pytest.mark.asyncio
    async def test_logout_requires_bearer_token(self, api_client) -> None:
        resp = await api_client.client.post("/api/v1/auth/logout")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "unauthenticated"


class TestRefresh:
    @pytest.mark.asyncio
    async def test_refresh_issues_new_access_and_refresh_tokens(self, api_client) -> None:
        await register_and_verify(api_client, email="frank@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "frank@example.com", "password": _PASSWORD},
        )
        assert login.status_code == 200
        old_refresh = login.cookies["vayunx_refresh_token"]

        # No body — the refresh token rides along automatically as the
        # HttpOnly cookie the login response just set.
        resp = await api_client.client.post("/api/v1/auth/refresh")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["access_token"].count(".") == 2
        assert "refresh_token" not in body
        assert resp.cookies["vayunx_refresh_token"] != old_refresh

        # The new access token actually authenticates a protected route.
        logout = await api_client.client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {body['access_token']}"}
        )
        assert logout.status_code == 204

    @pytest.mark.asyncio
    async def test_refresh_rejects_missing_cookie(self, api_client) -> None:
        resp = await api_client.client.post("/api/v1/auth/refresh")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "unauthenticated"

    @pytest.mark.asyncio
    async def test_refresh_rejects_bogus_token(self, api_client) -> None:
        resp = await api_client.client.post(
            "/api/v1/auth/refresh",
            headers={"Cookie": "vayunx_refresh_token=totally-bogus-refresh-token"},
        )
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_refresh_token"

    @pytest.mark.asyncio
    async def test_refresh_rejects_reuse_of_a_rotated_token(self, api_client) -> None:
        # Rotation means the OLD refresh token is dead the moment it's redeemed
        # once — replaying it (e.g. a stolen/leaked copy) must fail. The
        # client's cookie jar auto-updates to the rotated cookie after the
        # first call, so the OLD value is pinned explicitly on the second
        # request to simulate exactly that replay.
        await register_and_verify(api_client, email="grace@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "grace@example.com", "password": _PASSWORD},
        )
        old_refresh = login.cookies["vayunx_refresh_token"]

        first = await api_client.client.post("/api/v1/auth/refresh")
        assert first.status_code == 200

        second = await api_client.client.post(
            "/api/v1/auth/refresh", headers={"Cookie": f"vayunx_refresh_token={old_refresh}"}
        )
        assert second.status_code == 401
        assert second.json()["error_code"] == "invalid_refresh_token"

    @pytest.mark.asyncio
    async def test_refresh_rejects_token_from_a_logged_out_session(self, api_client) -> None:
        await register_and_verify(api_client, email="heidi@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "heidi@example.com", "password": _PASSWORD},
        )
        access = login.json()["access_token"]
        refresh_token = login.cookies["vayunx_refresh_token"]

        await api_client.client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"}
        )

        # Logout clears the browser's cookie too, so pin the (now server-side
        # revoked) old value explicitly to prove IT specifically is rejected,
        # rather than merely testing "no cookie was sent".
        resp = await api_client.client.post(
            "/api/v1/auth/refresh", headers={"Cookie": f"vayunx_refresh_token={refresh_token}"}
        )
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "invalid_refresh_token"


class TestSessions:
    @pytest.mark.asyncio
    async def test_list_sessions_shows_the_current_session(self, api_client) -> None:
        await register_and_verify(api_client, email="victor@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login",
            json={
                "email": "victor@example.com",
                "password": _PASSWORD,
                "device_context": "Chrome on Windows",
            },
        )
        access = login.json()["access_token"]

        resp = await api_client.client.get(
            "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {access}"}
        )
        assert resp.status_code == 200, resp.text
        sessions = resp.json()
        assert len(sessions) == 1
        assert sessions[0]["device_context"] == "Chrome on Windows"
        assert sessions[0]["current"] is True
        assert sessions[0]["created_at"]
        assert sessions[0]["session_id"]

    @pytest.mark.asyncio
    async def test_list_sessions_shows_multiple_devices_with_only_one_current(
        self, api_client
    ) -> None:
        await register_and_verify(api_client, email="wendy@example.com", password=_PASSWORD)
        await api_client.client.post(
            "/api/v1/auth/login",
            json={
                "email": "wendy@example.com",
                "password": _PASSWORD,
                "device_context": "iPhone",
            },
        )
        second = await api_client.client.post(
            "/api/v1/auth/login",
            json={
                "email": "wendy@example.com",
                "password": _PASSWORD,
                "device_context": "Firefox on macOS",
            },
        )
        second_access = second.json()["access_token"]

        resp = await api_client.client.get(
            "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {second_access}"}
        )
        assert resp.status_code == 200, resp.text
        sessions = resp.json()
        assert len(sessions) == 2
        device_contexts = {s["device_context"] for s in sessions}
        assert device_contexts == {"iPhone", "Firefox on macOS"}
        # Only the session behind THIS request's bearer token (the second
        # login) is flagged current — the first (iPhone) is a different device.
        current = [s for s in sessions if s["current"]]
        assert len(current) == 1
        assert current[0]["device_context"] == "Firefox on macOS"

    @pytest.mark.asyncio
    async def test_revoke_a_non_current_session_removes_it_from_the_list(
        self, api_client
    ) -> None:
        await register_and_verify(api_client, email="xavier@example.com", password=_PASSWORD)
        await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "xavier@example.com", "password": _PASSWORD, "device_context": "iPad"},
        )
        second = await api_client.client.post(
            "/api/v1/auth/login",
            json={
                "email": "xavier@example.com",
                "password": _PASSWORD,
                "device_context": "Android",
            },
        )
        second_access = second.json()["access_token"]

        listing = await api_client.client.get(
            "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {second_access}"}
        )
        ipad_session = next(s for s in listing.json() if s["device_context"] == "iPad")

        revoke = await api_client.client.request(
            "DELETE",
            f"/api/v1/auth/sessions/{ipad_session['session_id']}",
            headers={"Authorization": f"Bearer {second_access}"},
        )
        assert revoke.status_code == 204

        after = await api_client.client.get(
            "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {second_access}"}
        )
        assert len(after.json()) == 1
        assert after.json()[0]["device_context"] == "Android"

    @pytest.mark.asyncio
    async def test_revoke_the_current_session_clears_its_own_cookie_and_access(
        self, api_client
    ) -> None:
        await register_and_verify(api_client, email="yusuf@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "yusuf@example.com", "password": _PASSWORD},
        )
        access = login.json()["access_token"]
        listing = await api_client.client.get(
            "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {access}"}
        )
        session_id = listing.json()[0]["session_id"]

        revoke = await api_client.client.request(
            "DELETE",
            f"/api/v1/auth/sessions/{session_id}",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert revoke.status_code == 204
        assert revoke.cookies.get("vayunx_refresh_token") is None

        # The access token is now dead too — its backing session is revoked.
        again = await api_client.client.get(
            "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {access}"}
        )
        assert again.status_code == 401
        assert again.json()["error_code"] == "unauthenticated"

    @pytest.mark.asyncio
    async def test_revoke_rejects_a_session_belonging_to_another_user(self, api_client) -> None:
        await register_and_verify(api_client, email="zack@example.com", password=_PASSWORD)
        zack_login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "zack@example.com", "password": _PASSWORD}
        )
        zack_access = zack_login.json()["access_token"]
        zack_sessions = await api_client.client.get(
            "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {zack_access}"}
        )
        zack_session_id = zack_sessions.json()[0]["session_id"]

        await register_and_verify(api_client, email="amy2@example.com", password=_PASSWORD)
        amy_login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "amy2@example.com", "password": _PASSWORD}
        )
        amy_access = amy_login.json()["access_token"]

        resp = await api_client.client.request(
            "DELETE",
            f"/api/v1/auth/sessions/{zack_session_id}",
            headers={"Authorization": f"Bearer {amy_access}"},
        )
        assert resp.status_code == 404
        assert resp.json()["error_code"] == "session_not_found"

    @pytest.mark.asyncio
    async def test_revoke_rejects_an_unknown_session_id(self, api_client) -> None:
        await register_and_verify(api_client, email="beth@example.com", password=_PASSWORD)
        login = await api_client.client.post(
            "/api/v1/auth/login", json={"email": "beth@example.com", "password": _PASSWORD}
        )
        access = login.json()["access_token"]

        resp = await api_client.client.request(
            "DELETE",
            "/api/v1/auth/sessions/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert resp.status_code == 404
        assert resp.json()["error_code"] == "session_not_found"

    @pytest.mark.asyncio
    async def test_list_sessions_requires_bearer_token(self, api_client) -> None:
        resp = await api_client.client.get("/api/v1/auth/sessions")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "unauthenticated"
