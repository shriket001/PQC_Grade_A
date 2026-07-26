"""OIDC Relying Party endpoints — login via an external OIDC provider (FR-010
inbound direction). Google is the first (and currently only) configured
provider; `{provider}` is already parameterized so a second provider later is
just another entry in `get_oidc_clients()` — no router change needed.

Both endpoints are top-level browser navigations (302 redirects), not JSON
APIs: `/authorize` sends the browser to the external IdP, and the IdP later
redirects the browser back to `/callback` with `?code=&state=`. So on
success, `/callback` can't hand tokens back as a JSON body — it sets the
HttpOnly refresh cookie (exactly like `/auth/login`) and redirects to the
frontend root, where `AuthBootstrap` already silently mints an access token
from that cookie via `/auth/refresh`. No dedicated frontend route is needed.
"""

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse

from src.api.v1.cookies import set_refresh_cookie
from src.core.config import get_settings
from src.core.dependencies import get_oidc_service
from src.services.errors import (
    AccountDisabledError,
    ExternalIdentityConflictError,
    OAuthExchangeFailedError,
    OAuthProviderNotSupportedError,
)
from src.services.oidc_service import OidcService

router = APIRouter()

_settings = get_settings()

# Short-lived, HttpOnly, scoped to this router's own path — proves the
# browser completing `/callback` is the same one `/authorize` sent to the IdP
# (CSRF/login-replay defense for the OAuth authorization-code flow).
_STATE_COOKIE_NAME = "vayunx_oauth_state"
_STATE_COOKIE_PATH = "/api/v1/auth/oidc"
_STATE_TTL_SECONDS = 600


def _login_redirect(error_code: str) -> RedirectResponse:
    resp = RedirectResponse(f"{_settings.app_base_url}/login?error={error_code}", status_code=302)
    resp.delete_cookie(_STATE_COOKIE_NAME, path=_STATE_COOKIE_PATH)
    return resp


@router.get("/oidc/{provider}/authorize")
async def oidc_authorize(
    provider: str,
    oidc_service: Annotated[OidcService, Depends(get_oidc_service)],
) -> RedirectResponse:
    state = secrets.token_urlsafe(24)
    try:
        url = oidc_service.build_authorization_url(provider, state)
    except OAuthProviderNotSupportedError:
        return _login_redirect("oauth_unavailable")

    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(
        key=_STATE_COOKIE_NAME,
        value=state,
        max_age=_STATE_TTL_SECONDS,
        path=_STATE_COOKIE_PATH,
        httponly=True,
        secure=_settings.refresh_cookie_secure,
        samesite="lax",
    )
    return resp


@router.get("/oidc/{provider}/callback")
async def oidc_callback(
    provider: str,
    request: Request,
    oidc_service: Annotated[OidcService, Depends(get_oidc_service)],
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
) -> RedirectResponse:
    cookie_state = request.cookies.get(_STATE_COOKIE_NAME)
    if (
        error
        or not code
        or not state
        or not cookie_state
        or not secrets.compare_digest(state, cookie_state)
    ):
        return _login_redirect("oauth_failed")

    try:
        _tokens, raw_refresh = await oidc_service.handle_callback(provider, code)
    except (
        OAuthProviderNotSupportedError,
        OAuthExchangeFailedError,
        ExternalIdentityConflictError,
        AccountDisabledError,
    ):
        return _login_redirect("oauth_failed")

    resp = RedirectResponse(_settings.app_base_url, status_code=302)
    resp.delete_cookie(_STATE_COOKIE_NAME, path=_STATE_COOKIE_PATH)
    set_refresh_cookie(resp, raw_refresh, settings=_settings)
    return resp
