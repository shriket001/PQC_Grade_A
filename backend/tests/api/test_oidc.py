"""API tests for the OIDC Relying Party login flow (FR-010 inbound direction,
`/auth/oidc/{provider}/authorize` + `/callback`), configured for Google.

A `FakeOidcClient` stands in for `GoogleOidcClient` via a `get_oidc_clients`
dependency override — no real network calls or Google credentials needed;
`GoogleOidcClient` itself (the HTTP-calling part) is intentionally NOT
exercised here, since hitting real Google endpoints isn't something a test
suite should depend on.
"""

from urllib.parse import parse_qs, urlparse

import pytest

from src.core.dependencies import get_oidc_clients
from src.main import app
from src.services.oidc_client import OidcClient, OidcExchangeError, OidcProfile
from tests.conftest import register_and_verify

_PASSWORD = "Sup3rSecretPass!"
_ISSUER = "https://fake-idp.example"


class FakeOidcClient(OidcClient):
    """Test double: returns a canned profile (or raises) instead of calling Google."""

    def __init__(self, profile: OidcProfile | None = None, error: Exception | None = None) -> None:
        self.profile = profile
        self.error = error
        self.exchanged_codes: list[str] = []

    def authorization_url(self, state: str) -> str:
        return f"https://fake-idp.example/authorize?state={state}"

    async def exchange_code(self, code: str) -> OidcProfile:
        self.exchanged_codes.append(code)
        if self.error is not None:
            raise self.error
        assert self.profile is not None
        return self.profile


def _install_fake_client(client: FakeOidcClient) -> None:
    app.dependency_overrides[get_oidc_clients] = lambda: {"google": client}


def _extract_state(authorize_location: str) -> str:
    query = parse_qs(urlparse(authorize_location).query)
    return query["state"][0]


async def _do_authorize(api_client) -> str:
    """Hits /authorize and returns the `state` value the server generated
    (the redirect cookie jar already carries the matching cookie)."""
    resp = await api_client.client.get(
        "/api/v1/auth/oidc/google/authorize", follow_redirects=False
    )
    assert resp.status_code == 302, resp.text
    assert resp.cookies.get("vayunx_oauth_state")
    return _extract_state(resp.headers["location"])


class TestAuthorize:
    @pytest.mark.asyncio
    async def test_authorize_redirects_to_the_idp_and_sets_a_state_cookie(
        self, api_client
    ) -> None:
        _install_fake_client(FakeOidcClient())
        resp = await api_client.client.get(
            "/api/v1/auth/oidc/google/authorize", follow_redirects=False
        )
        assert resp.status_code == 302
        assert resp.headers["location"].startswith("https://fake-idp.example/authorize?state=")
        assert resp.cookies.get("vayunx_oauth_state")

    @pytest.mark.asyncio
    async def test_authorize_for_an_unconfigured_provider_redirects_to_login_error(
        self, api_client
    ) -> None:
        app.dependency_overrides[get_oidc_clients] = lambda: {}
        resp = await api_client.client.get(
            "/api/v1/auth/oidc/google/authorize", follow_redirects=False
        )
        assert resp.status_code == 302
        assert "error=oauth_unavailable" in resp.headers["location"]
        assert "/login" in resp.headers["location"]


class TestCallback:
    @pytest.mark.asyncio
    async def test_first_time_login_creates_a_user_and_local_session(self, api_client) -> None:
        profile = OidcProfile(
            issuer=_ISSUER,
            subject="google-sub-1",
            email="newperson@example.com",
            email_verified=True,
            name="New Person",
        )
        client = FakeOidcClient(profile=profile)
        _install_fake_client(client)
        state = await _do_authorize(api_client)

        resp = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"code": "auth-code-1", "state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302, resp.text
        assert resp.headers["location"] == "http://localhost:5173"
        assert resp.cookies.get("vayunx_refresh_token")
        assert client.exchanged_codes == ["auth-code-1"]

        # The session this created actually works end-to-end.
        refreshed = await api_client.client.post("/api/v1/auth/refresh")
        assert refreshed.status_code == 200, refreshed.text
        me = await api_client.client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {refreshed.json()['access_token']}"},
        )
        assert me.status_code == 200
        assert me.json()["email"] == "newperson@example.com"
        assert me.json()["email_verified"] is True

    @pytest.mark.asyncio
    async def test_repeat_login_with_the_same_subject_reuses_the_same_user(
        self, api_client
    ) -> None:
        profile = OidcProfile(
            issuer=_ISSUER,
            subject="google-sub-2",
            email="repeat@example.com",
            email_verified=True,
            name="Repeat User",
        )
        client = FakeOidcClient(profile=profile)
        _install_fake_client(client)

        state1 = await _do_authorize(api_client)
        first = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"code": "code-a", "state": state1},
            follow_redirects=False,
        )
        first_refreshed = await api_client.client.post("/api/v1/auth/refresh")
        first_id = (
            await api_client.client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {first_refreshed.json()['access_token']}"},
            )
        ).json()["id"]

        state2 = await _do_authorize(api_client)
        second = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"code": "code-b", "state": state2},
            follow_redirects=False,
        )
        second_refreshed = await api_client.client.post("/api/v1/auth/refresh")
        second_id = (
            await api_client.client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {second_refreshed.json()['access_token']}"},
            )
        ).json()["id"]

        assert first.status_code == 302
        assert second.status_code == 302
        assert first_id == second_id

    @pytest.mark.asyncio
    async def test_verified_email_match_links_to_an_existing_password_account(
        self, api_client
    ) -> None:
        registered = await register_and_verify(
            api_client, email="alreadyhere@example.com", password=_PASSWORD
        )

        profile = OidcProfile(
            issuer=_ISSUER,
            subject="google-sub-3",
            email="alreadyhere@example.com",
            email_verified=True,
            name="Already Here",
        )
        _install_fake_client(FakeOidcClient(profile=profile))
        state = await _do_authorize(api_client)

        callback = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"code": "code-link", "state": state},
            follow_redirects=False,
        )
        assert callback.status_code == 302
        refreshed = await api_client.client.post("/api/v1/auth/refresh")
        me = await api_client.client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {refreshed.json()['access_token']}"},
        )
        # Same account as the one created by password registration — not a
        # second, duplicate user.
        assert me.json()["id"] == registered["user_id"]

    @pytest.mark.asyncio
    async def test_unverified_email_matching_an_existing_account_is_refused(
        self, api_client
    ) -> None:
        # Neither safe option is available: linking would trust an email the
        # IdP itself won't vouch for (spoofing risk), and creating a second
        # user is impossible anyway (email is globally unique) — must refuse
        # rather than silently doing either, or (as this used to) crashing.
        await register_and_verify(api_client, email="careful@example.com", password=_PASSWORD)

        profile = OidcProfile(
            issuer=_ISSUER,
            subject="google-sub-4",
            email="careful@example.com",
            email_verified=False,  # IdP itself doesn't vouch for this email
            name="Careful",
        )
        _install_fake_client(FakeOidcClient(profile=profile))
        state = await _do_authorize(api_client)

        resp = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"code": "code-unverified", "state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_failed" in resp.headers["location"]
        assert resp.cookies.get("vayunx_refresh_token") is None
        # The original password account is completely untouched by the
        # rejected attempt — same password login still works.
        login = await api_client.client.post(
            "/api/v1/auth/login",
            json={"email": "careful@example.com", "password": _PASSWORD},
        )
        assert login.status_code == 200

    @pytest.mark.asyncio
    async def test_unverified_email_with_no_existing_account_creates_a_new_user(
        self, api_client
    ) -> None:
        # Unverified is only a problem when it collides with an existing
        # account's email — with no collision, there's nothing risky about
        # creating a fresh account (same as any first-time sign-in).
        profile = OidcProfile(
            issuer=_ISSUER,
            subject="google-sub-5",
            email="brandnew@example.com",
            email_verified=False,
            name="Brand New",
        )
        _install_fake_client(FakeOidcClient(profile=profile))
        state = await _do_authorize(api_client)

        resp = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"code": "code-fresh-unverified", "state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.cookies.get("vayunx_refresh_token")

    @pytest.mark.asyncio
    async def test_state_mismatch_redirects_to_login_error_without_a_session(
        self, api_client
    ) -> None:
        _install_fake_client(FakeOidcClient(profile=None))
        await _do_authorize(api_client)

        resp = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"code": "some-code", "state": "totally-wrong-state"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_failed" in resp.headers["location"]
        assert resp.cookies.get("vayunx_refresh_token") is None

    @pytest.mark.asyncio
    async def test_idp_error_param_redirects_to_login_error(self, api_client) -> None:
        _install_fake_client(FakeOidcClient(profile=None))
        state = await _do_authorize(api_client)

        resp = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"error": "access_denied", "state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_failed" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_exchange_failure_redirects_to_login_error(self, api_client) -> None:
        _install_fake_client(FakeOidcClient(error=OidcExchangeError("boom")))
        state = await _do_authorize(api_client)

        resp = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"code": "any-code", "state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_failed" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_callback_for_an_unconfigured_provider_redirects_to_login_error(
        self, api_client
    ) -> None:
        _install_fake_client(FakeOidcClient(profile=None))
        state = await _do_authorize(api_client)
        # Provider goes away between /authorize and /callback (e.g. config
        # reload) — should fail the same way as never having been configured.
        app.dependency_overrides[get_oidc_clients] = lambda: {}

        resp = await api_client.client.get(
            "/api/v1/auth/oidc/google/callback",
            params={"code": "any-code", "state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_failed" in resp.headers["location"]
