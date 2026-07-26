"""Shared HttpOnly refresh-token cookie helpers (FR-005/US10).

Used by both `auth.py` (login/refresh/logout/session-revoke) and `oidc.py`
(OAuth/OIDC login callback) so the cookie's name/path/flags can't drift
between the two places that set/clear it.
"""

from fastapi import Response

from src.core.config import Settings

# HttpOnly so no client-side JS (and thus no XSS payload) can ever read the
# refresh token; scoped to this router's own path so it's never sent on
# unrelated /api/v1/* calls.
REFRESH_COOKIE_NAME = "vayunx_refresh_token"
REFRESH_COOKIE_PATH = "/api/v1/auth"


def set_refresh_cookie(response: Response, raw_refresh_token: str, *, settings: Settings) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=raw_refresh_token,
        max_age=settings.jwt_refresh_token_ttl_seconds,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="lax",
    )


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH)
