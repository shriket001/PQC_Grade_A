"""SAML Relying Party / Service Provider endpoints — login via an external
SAML IdP (FR-011 inbound direction). `{idp}` is parameterized (default name
"samltest", configurable via `SAML_IDP_NAME`) so a second IdP later is just
another entry in `get_saml_clients()` — no router change needed.

Like the OIDC flow, both endpoints are top-level browser operations, not JSON
APIs: `/login` redirects the browser to the external IdP, and the IdP's own
page then auto-submits a POSTed HTML form (`SAMLResponse`) to `/acs` — the
standard SAML "HTTP-POST binding". On success, `/acs` sets the HttpOnly
refresh cookie (exactly like `/auth/login`) and redirects to the frontend
root, where `AuthBootstrap` silently mints an access token from that cookie
via `/auth/refresh`. No dedicated frontend route is needed.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from src.api.v1.cookies import set_refresh_cookie
from src.core.config import get_settings
from src.core.dependencies import get_saml_service
from src.services.errors import (
    AccountDisabledError,
    ExternalIdentityConflictError,
    SamlAssertionRejectedError,
    SamlProviderNotSupportedError,
)
from src.services.saml_service import SamlService

router = APIRouter()

_settings = get_settings()

# Short-lived, HttpOnly, scoped to this router's own path — binds the POST
# that eventually arrives at /acs to the specific /login redirect that
# started it (replay/unsolicited-response defense for the SAML flow).
_REQUEST_ID_COOKIE_NAME = "vayunx_saml_request_id"
_REQUEST_ID_COOKIE_PATH = "/api/v1/auth/saml"
_REQUEST_ID_TTL_SECONDS = 600


def _login_redirect(error_code: str) -> RedirectResponse:
    resp = RedirectResponse(f"{_settings.app_base_url}/login?error={error_code}", status_code=302)
    resp.delete_cookie(_REQUEST_ID_COOKIE_NAME, path=_REQUEST_ID_COOKIE_PATH)
    return resp


@router.get("/saml/{idp}/login")
async def saml_login(
    idp: str,
    saml_service: Annotated[SamlService, Depends(get_saml_service)],
) -> RedirectResponse:
    try:
        redirect_url, request_id = saml_service.build_login_redirect(idp, relay_state="")
    except SamlProviderNotSupportedError:
        return _login_redirect("saml_unavailable")

    resp = RedirectResponse(redirect_url, status_code=302)
    resp.set_cookie(
        key=_REQUEST_ID_COOKIE_NAME,
        value=request_id,
        max_age=_REQUEST_ID_TTL_SECONDS,
        path=_REQUEST_ID_COOKIE_PATH,
        httponly=True,
        secure=_settings.refresh_cookie_secure,
        # The IdP's own page is what performs the POST to /acs (a genuine
        # cross-site navigation from the browser's point of view), so this
        # cookie must be sent on that cross-site POST — "lax" would drop it.
        samesite="none",
    )
    return resp


@router.post("/saml/{idp}/acs")
async def saml_acs(
    idp: str,
    request: Request,
    saml_service: Annotated[SamlService, Depends(get_saml_service)],
    SAMLResponse: Annotated[str, Form()],
) -> RedirectResponse:
    request_id = request.cookies.get(_REQUEST_ID_COOKIE_NAME)
    if not request_id:
        return _login_redirect("saml_failed")

    try:
        _tokens, raw_refresh = await saml_service.handle_acs(idp, SAMLResponse, request_id)
    except (
        SamlProviderNotSupportedError,
        SamlAssertionRejectedError,
        ExternalIdentityConflictError,
        AccountDisabledError,
    ):
        return _login_redirect("saml_failed")

    resp = RedirectResponse(_settings.app_base_url, status_code=302)
    resp.delete_cookie(_REQUEST_ID_COOKIE_NAME, path=_REQUEST_ID_COOKIE_PATH)
    set_refresh_cookie(resp, raw_refresh, settings=_settings)
    return resp


@router.get("/saml/{idp}/metadata")
async def saml_metadata(
    idp: str,
    saml_service: Annotated[SamlService, Depends(get_saml_service)],
) -> PlainTextResponse:
    """This SP's own metadata XML — hand this to the external IdP (e.g.
    upload it at samltest.id) when registering this app as a Service
    Provider. Not part of the login flow itself."""
    try:
        xml = saml_service.metadata_xml(idp)
    except SamlProviderNotSupportedError:
        return PlainTextResponse("SAML is not configured for this idp.", status_code=404)
    return PlainTextResponse(xml, media_type="application/xml")
