"""Auth endpoints — register / verify-email / login / logout (US1 / Phase 4).

All bodies are strict Pydantic DTOs; all auth-domain errors surface through the
shared `{error_code, message}` shape via the `AuthError` handler in main.py.
Login and registration are rate-limited per FR-014 (T045).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from src.api.v1.cookies import REFRESH_COOKIE_NAME, clear_refresh_cookie, set_refresh_cookie
from src.core.config import get_settings
from src.core.dependencies import AuthContext, get_auth_service, get_current_session
from src.core.rate_limit import limiter
from src.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    RegisterResponse,
    SessionResponse,
    TokenResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
)
from src.services.auth_service import AuthService
from src.services.errors import UnauthenticatedError

router = APIRouter()

_settings = get_settings()
_LOGIN_LIMIT = f"{_settings.rate_limit_login_per_minute}/minute"
_REGISTER_LIMIT = f"{_settings.rate_limit_register_per_minute}/minute"


@router.post("/register", response_model=RegisterResponse, status_code=201)
@limiter.limit(_REGISTER_LIMIT)
async def register(
    request: Request,
    body: RegisterRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> RegisterResponse:
    user = await auth_service.register(
        email=body.email, password=body.password, username=body.username
    )
    return RegisterResponse(user_id=user.id, username=user.username, status="unverified")


@router.post("/verify-email", response_model=VerifyEmailResponse)
async def verify_email(
    body: VerifyEmailRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> VerifyEmailResponse:
    verified = await auth_service.verify_email(body.verification_token)
    return VerifyEmailResponse(verified=verified)


@router.post("/login", response_model=TokenResponse)
@limiter.limit(_LOGIN_LIMIT)
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> TokenResponse:
    tokens, raw_refresh = await auth_service.login(
        email=body.email,
        password=body.password,
        device_context=body.device_context,
        totp_code=body.totp_code,
    )
    set_refresh_cookie(response, raw_refresh, settings=_settings)
    return tokens


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> TokenResponse:
    raw_refresh = request.cookies.get(REFRESH_COOKIE_NAME)
    if not raw_refresh:
        raise UnauthenticatedError("missing refresh token")
    tokens, new_raw_refresh = await auth_service.refresh(refresh_token=raw_refresh)
    set_refresh_cookie(response, new_raw_refresh, settings=_settings)
    return tokens


@router.post("/logout", status_code=204)
async def logout(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    await auth_service.logout(ctx.session)
    # Building the Response directly here (rather than mutating an injected
    # `Response` param and returning a separate one) — FastAPI only merges an
    # injected `Response`'s headers/cookies when the handler returns a plain
    # model; returning your OWN `Response` instance replaces it wholesale, so
    # the cookie-clear has to land on the actual object being returned.
    resp = Response(status_code=204)
    clear_refresh_cookie(resp)
    return resp


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> list[SessionResponse]:
    sessions = await auth_service.list_sessions(ctx.user.id)
    return [
        SessionResponse(
            session_id=s.id,
            device_context=s.device_context,
            created_at=s.created_at,
            current=s.id == ctx.session.id,
        )
        for s in sessions
    ]


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_session(
    session_id: UUID,
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    await auth_service.revoke_session(user_id=ctx.user.id, session_id=session_id)
    resp = Response(status_code=204)
    # Revoking your OWN currently-active session (rather than another device)
    # kills the very refresh token this browser holds — clear its cookie too,
    # same as logout, so a stale dead cookie doesn't linger client-side.
    if session_id == ctx.session.id:
        clear_refresh_cookie(resp)
    return resp
