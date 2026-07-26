"""API tests for the user-directory surface (US2 user discovery — FR-052/FR-053):

- GET /users/me         — self profile (incl. email + verification status)
- GET /users/search?q=  — username PREFIX resolution (case-insensitive, capped +
                          rate-limited, `min_length=2`), used both to verify a
                          peer exists and to power an autocomplete picker;
                          never returns email
- GET /users/{user_id}  — public summary by id (username + display_name; no email)

Plus an end-to-end integration test that starts a conversation by resolving a
username through the directory — the enterprise-standard flow, no out-of-band
session/UUID copying.
"""

import uuid

import pytest

from tests.conftest import TestApp, register_and_verify, username_from_email

_PASSWORD = "Sup3rSecretPass!"


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _register_login(
    api_client: TestApp, *, email: str, username: str | None = None
) -> tuple[str, str, str]:
    """Register, verify, login. Returns (user_id, username, access_token)."""
    handle = username or username_from_email(email)
    reg = await register_and_verify(api_client, email=email, password=_PASSWORD, username=handle)
    login = await api_client.client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": _PASSWORD, "device_context": "web"},
    )
    assert login.status_code == 200, login.text
    return reg["user_id"], reg["username"], login.json()["access_token"]


@pytest.mark.asyncio
class TestUserProfile:
    async def test_users_me_returns_profile_with_username(self, api_client) -> None:
        user_id, username, token = await _register_login(
            api_client, email="me@example.com", username="myself"
        )
        resp = await api_client.client.get("/api/v1/users/me", headers=_headers(token))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == user_id
        assert body["username"] == "myself"
        # display_name defaults to the username at registration.
        assert body["display_name"] == "myself"
        assert body["email"] == "me@example.com"
        assert body["email_verified"] is True
        assert body["created_at"]
        assert body["mfa_enabled"] is False

    async def test_users_me_requires_auth(self, api_client) -> None:
        resp = await api_client.client.get("/api/v1/users/me")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "unauthenticated"


@pytest.mark.asyncio
class TestUserSearch:
    async def test_search_returns_exact_user_without_email(self, api_client) -> None:
        bob_id, _, _ = await _register_login(api_client, email="bob@example.com", username="bob")
        _, _, alice_token = await _register_login(
            api_client, email="alice@example.com", username="alice"
        )

        resp = await api_client.client.get(
            "/api/v1/users/search?q=bob", headers=_headers(alice_token)
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body) == 1
        assert body[0]["id"] == bob_id
        assert body[0]["username"] == "bob"
        assert body[0]["display_name"] == "bob"
        # The directory projection MUST NOT expose email (FR-022 / PII).
        assert "email" not in body[0]

    async def test_search_is_case_insensitive(self, api_client) -> None:
        await _register_login(api_client, email="ci@example.com", username="handle")
        _, _, token = await _register_login(
            api_client, email="seeker@example.com", username="seeker"
        )
        resp = await api_client.client.get("/api/v1/users/search?q=HANDLE", headers=_headers(token))
        assert resp.status_code == 200
        assert [u["username"] for u in resp.json()] == ["handle"]

    async def test_search_returns_empty_for_unknown_username(self, api_client) -> None:
        _, _, token = await _register_login(api_client, email="q@example.com", username="query")
        resp = await api_client.client.get("/api/v1/users/search?q=nobody", headers=_headers(token))
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_search_requires_auth(self, api_client) -> None:
        resp = await api_client.client.get("/api/v1/users/search?q=bob")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "unauthenticated"

    async def test_search_rejects_missing_query(self, api_client) -> None:
        _, _, token = await _register_login(api_client, email="mq@example.com", username="mquery")
        resp = await api_client.client.get("/api/v1/users/search", headers=_headers(token))
        assert resp.status_code == 422  # `q` is required

    async def test_search_rejects_single_character_query(self, api_client) -> None:
        # min_length=2 keeps a single keystroke from scanning the whole table.
        _, _, token = await _register_login(api_client, email="sc@example.com", username="scquery")
        resp = await api_client.client.get("/api/v1/users/search?q=b", headers=_headers(token))
        assert resp.status_code == 422

    async def test_search_matches_by_prefix_and_is_capped_alphabetical(self, api_client) -> None:
        await _register_login(api_client, email="bob1@example.com", username="bob")
        await _register_login(api_client, email="bob2@example.com", username="bobby")
        await _register_login(api_client, email="bob3@example.com", username="bobcat")
        _, _, token = await _register_login(
            api_client, email="prefix-seeker@example.com", username="prefixseeker"
        )
        resp = await api_client.client.get("/api/v1/users/search?q=bob", headers=_headers(token))
        assert resp.status_code == 200, resp.text
        assert [u["username"] for u in resp.json()] == ["bob", "bobby", "bobcat"]


@pytest.mark.asyncio
class TestUserSummary:
    async def test_get_user_summary_by_id_without_email(self, api_client) -> None:
        bob_id, _, _ = await _register_login(api_client, email="s@example.com", username="sum")
        _, _, alice_token = await _register_login(
            api_client, email="s2@example.com", username="asker"
        )
        resp = await api_client.client.get(f"/api/v1/users/{bob_id}", headers=_headers(alice_token))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == bob_id
        assert body["username"] == "sum"
        assert body["display_name"] == "sum"
        assert "email" not in body  # public summary never exposes email

    async def test_get_user_summary_unknown_id_returns_404(self, api_client) -> None:
        _, _, token = await _register_login(api_client, email="u@example.com", username="who")
        resp = await api_client.client.get(f"/api/v1/users/{uuid.uuid4()}", headers=_headers(token))
        assert resp.status_code == 404
        assert resp.json()["error_code"] == "user_not_found"

    async def test_get_user_summary_requires_auth(self, api_client) -> None:
        resp = await api_client.client.get(f"/api/v1/users/{uuid.uuid4()}")
        assert resp.status_code == 401
        assert resp.json()["error_code"] == "unauthenticated"


@pytest.mark.asyncio
class TestStartConversationByUsername:
    async def test_resolve_username_then_create_direct_conversation(self, api_client) -> None:
        """Enterprise-standard flow: resolve the peer by username through the
        directory, then create the direct conversation with the resolved id —
        no out-of-band session/UUID copying."""
        bob_id, _, _ = await _register_login(api_client, email="peer@example.com", username="bob")
        _, _, alice_token = await _register_login(
            api_client, email="starter@example.com", username="alice"
        )

        found = await api_client.client.get(
            "/api/v1/users/search?q=bob", headers=_headers(alice_token)
        )
        assert found.status_code == 200
        matches = found.json()
        assert len(matches) == 1
        resolved_peer_id = matches[0]["id"]
        assert resolved_peer_id == bob_id

        conv = await api_client.client.post(
            "/api/v1/conversations",
            json={"type": "direct", "participant_user_ids": [resolved_peer_id]},
            headers=_headers(alice_token),
        )
        assert conv.status_code == 201, conv.text
        participants = {p["user_id"] for p in conv.json()["participants"]}
        assert resolved_peer_id in participants
