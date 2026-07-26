"""MFA/TOTP endpoints — enroll, confirm, disable (FR-009).

Mounted under the same `/auth` prefix as `auth.py` (paths match
contracts/rest-api.md: `/auth/mfa/totp/*`). All three require an
authenticated session — a factor is always scoped to the caller themselves;
there is no "manage someone else's MFA" path here (that's the separate,
admin-only FR-059 recovery flow, out of scope for this self-service router).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from src.core.config import get_settings
from src.core.dependencies import AuthContext, get_current_session, get_mfa_service
from src.core.rate_limit import limiter
from src.schemas.mfa import (
    MfaConfirmRequest,
    MfaConfirmResponse,
    MfaDisableRequest,
    MfaEnrollResponse,
)
from src.services.mfa_service import MfaService

router = APIRouter()

_settings = get_settings()
_MFA_VERIFY_LIMIT = f"{_settings.rate_limit_mfa_verify_per_minute}/minute"


@router.post("/mfa/totp/enroll", response_model=MfaEnrollResponse)
async def enroll(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    mfa_service: Annotated[MfaService, Depends(get_mfa_service)],
) -> MfaEnrollResponse:
    otpauth_uri, secret = await mfa_service.enroll(ctx.user)
    return MfaEnrollResponse(otpauth_uri=otpauth_uri, secret=secret)


@router.post("/mfa/totp/confirm", response_model=MfaConfirmResponse)
@limiter.limit(_MFA_VERIFY_LIMIT)
async def confirm(
    request: Request,
    body: MfaConfirmRequest,
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    mfa_service: Annotated[MfaService, Depends(get_mfa_service)],
) -> MfaConfirmResponse:
    await mfa_service.confirm(ctx.user, body.totp_code)
    return MfaConfirmResponse(enabled=True)


@router.delete("/mfa/totp", status_code=204)
async def disable(
    body: MfaDisableRequest,
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    mfa_service: Annotated[MfaService, Depends(get_mfa_service)],
) -> Response:
    await mfa_service.disable(ctx.user, password=body.password, totp_code=body.totp_code)
    return Response(status_code=204)
