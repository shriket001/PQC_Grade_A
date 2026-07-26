"""API tests for the SAML Relying Party login flow (FR-011 inbound direction,
`/auth/saml/{idp}/login` + `/acs`), configured against a fake IdP name.

A `FakeSamlClient` stands in for `Pysaml2SamlClient` via a `get_saml_clients`
dependency override — no real XML parsing/signature verification or a real
external IdP needed; `Pysaml2SamlClient` itself (the pysaml2-calling part) is
intentionally NOT exercised here, since that needs real SAML metadata/certs
and isn't something a test suite should depend on.
"""

import pytest

from src.core.dependencies import get_saml_clients
from src.main import app
from src.services.external_identity_linker import ExternalProfile
from src.services.saml_client import SamlClient, SamlExchangeError
from tests.conftest import register_and_verify

_PASSWORD = "Sup3rSecretPass!"
_ISSUER = "https://fake-saml-idp.example"
_IDP = "samltest"


class FakeSamlClient(SamlClient):
    """Test double: returns a canned profile (or raises) instead of parsing
    a real SAMLResponse."""

    def __init__(
        self, profile: ExternalProfile | None = None, error: Exception | None = None
    ) -> None:
        self.profile = profile
        self.error = error
        self.processed_responses: list[tuple[str, str]] = []

    def login_redirect(self, relay_state: str) -> tuple[str, str]:
        request_id = "fake-request-id"
        return f"https://fake-saml-idp.example/sso?RelayState={relay_state}", request_id

    def process_response(self, saml_response_b64: str, request_id: str) -> ExternalProfile:
        self.processed_responses.append((saml_response_b64, request_id))
        if self.error is not None:
            raise self.error
        assert self.profile is not None
        return self.profile

    def metadata_xml(self) -> str:
        return "<EntityDescriptor/>"


def _install_fake_client(client: FakeSamlClient) -> None:
    app.dependency_overrides[get_saml_clients] = lambda: {_IDP: client}


async def _do_login(api_client) -> None:
    """Hits /login so the request-id cookie is set in the client's jar
    (mirrors samltest.id sending the browser to /acs afterward)."""
    resp = await api_client.client.get(f"/api/v1/auth/saml/{_IDP}/login", follow_redirects=False)
    assert resp.status_code == 302, resp.text
    assert resp.cookies.get("vayunx_saml_request_id")


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_redirects_to_the_idp_and_sets_a_request_id_cookie(
        self, api_client
    ) -> None:
        _install_fake_client(FakeSamlClient())
        resp = await api_client.client.get(
            f"/api/v1/auth/saml/{_IDP}/login", follow_redirects=False
        )
        assert resp.status_code == 302
        assert resp.headers["location"].startswith("https://fake-saml-idp.example/sso")
        assert resp.cookies.get("vayunx_saml_request_id") == "fake-request-id"

    @pytest.mark.asyncio
    async def test_login_for_an_unconfigured_idp_redirects_to_login_error(self, api_client) -> None:
        app.dependency_overrides[get_saml_clients] = lambda: {}
        resp = await api_client.client.get(
            f"/api/v1/auth/saml/{_IDP}/login", follow_redirects=False
        )
        assert resp.status_code == 302
        assert "error=saml_unavailable" in resp.headers["location"]
        assert "/login" in resp.headers["location"]


class TestAcs:
    @pytest.mark.asyncio
    async def test_first_time_login_creates_a_user_and_local_session(self, api_client) -> None:
        profile = ExternalProfile(
            issuer=_ISSUER,
            subject="saml-subject-1",
            email="newperson@example.com",
            email_verified=True,
            name="New Person",
        )
        client = FakeSamlClient(profile=profile)
        _install_fake_client(client)
        await _do_login(api_client)

        resp = await api_client.client.post(
            f"/api/v1/auth/saml/{_IDP}/acs",
            data={"SAMLResponse": "base64-blob"},
            follow_redirects=False,
        )
        assert resp.status_code == 302, resp.text
        assert resp.headers["location"] == "http://localhost:5173"
        assert resp.cookies.get("vayunx_refresh_token")
        assert client.processed_responses == [("base64-blob", "fake-request-id")]

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
        profile = ExternalProfile(
            issuer=_ISSUER,
            subject="saml-subject-2",
            email="repeat@example.com",
            email_verified=True,
            name="Repeat User",
        )
        client = FakeSamlClient(profile=profile)
        _install_fake_client(client)

        await _do_login(api_client)
        await api_client.client.post(
            f"/api/v1/auth/saml/{_IDP}/acs",
            data={"SAMLResponse": "blob-a"},
            follow_redirects=False,
        )
        first_refreshed = await api_client.client.post("/api/v1/auth/refresh")
        first_id = (
            await api_client.client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {first_refreshed.json()['access_token']}"},
            )
        ).json()["id"]

        await _do_login(api_client)
        await api_client.client.post(
            f"/api/v1/auth/saml/{_IDP}/acs",
            data={"SAMLResponse": "blob-b"},
            follow_redirects=False,
        )
        second_refreshed = await api_client.client.post("/api/v1/auth/refresh")
        second_id = (
            await api_client.client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {second_refreshed.json()['access_token']}"},
            )
        ).json()["id"]

        assert first_id == second_id

    @pytest.mark.asyncio
    async def test_verified_email_match_links_to_an_existing_password_account(
        self, api_client
    ) -> None:
        registered = await register_and_verify(
            api_client, email="alreadyhere-saml@example.com", password=_PASSWORD
        )

        profile = ExternalProfile(
            issuer=_ISSUER,
            subject="saml-subject-3",
            email="alreadyhere-saml@example.com",
            email_verified=True,
            name="Already Here",
        )
        _install_fake_client(FakeSamlClient(profile=profile))
        await _do_login(api_client)

        await api_client.client.post(
            f"/api/v1/auth/saml/{_IDP}/acs",
            data={"SAMLResponse": "blob"},
            follow_redirects=False,
        )
        refreshed = await api_client.client.post("/api/v1/auth/refresh")
        me = await api_client.client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {refreshed.json()['access_token']}"},
        )
        assert me.json()["id"] == registered["user_id"]

    @pytest.mark.asyncio
    async def test_unverified_email_matching_an_existing_account_is_refused(
        self, api_client
    ) -> None:
        await register_and_verify(api_client, email="careful-saml@example.com", password=_PASSWORD)

        profile = ExternalProfile(
            issuer=_ISSUER,
            subject="saml-subject-4",
            email="careful-saml@example.com",
            email_verified=False,
            name="Careful",
        )
        _install_fake_client(FakeSamlClient(profile=profile))
        await _do_login(api_client)

        resp = await api_client.client.post(
            f"/api/v1/auth/saml/{_IDP}/acs",
            data={"SAMLResponse": "blob"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=saml_failed" in resp.headers["location"]
        assert resp.cookies.get("vayunx_refresh_token") is None

    @pytest.mark.asyncio
    async def test_acs_without_a_request_id_cookie_redirects_to_login_error(
        self, api_client
    ) -> None:
        # A POST to /acs that never went through /login first — no cookie on hand.
        _install_fake_client(FakeSamlClient())
        resp = await api_client.client.post(
            f"/api/v1/auth/saml/{_IDP}/acs",
            data={"SAMLResponse": "blob"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=saml_failed" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_assertion_validation_failure_redirects_to_login_error(self, api_client) -> None:
        _install_fake_client(FakeSamlClient(error=SamlExchangeError("bad signature")))
        await _do_login(api_client)

        resp = await api_client.client.post(
            f"/api/v1/auth/saml/{_IDP}/acs",
            data={"SAMLResponse": "blob"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=saml_failed" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_acs_for_an_unconfigured_idp_redirects_to_login_error(self, api_client) -> None:
        _install_fake_client(FakeSamlClient())
        await _do_login(api_client)
        app.dependency_overrides[get_saml_clients] = lambda: {}

        resp = await api_client.client.post(
            f"/api/v1/auth/saml/{_IDP}/acs",
            data={"SAMLResponse": "blob"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=saml_failed" in resp.headers["location"]


class TestMetadata:
    @pytest.mark.asyncio
    async def test_metadata_returns_the_sp_xml(self, api_client) -> None:
        _install_fake_client(FakeSamlClient())
        resp = await api_client.client.get(f"/api/v1/auth/saml/{_IDP}/metadata")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/xml")
        assert "EntityDescriptor" in resp.text

    @pytest.mark.asyncio
    async def test_metadata_for_an_unconfigured_idp_is_404(self, api_client) -> None:
        app.dependency_overrides[get_saml_clients] = lambda: {}
        resp = await api_client.client.get(f"/api/v1/auth/saml/{_IDP}/metadata")
        assert resp.status_code == 404
