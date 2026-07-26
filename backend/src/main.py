"""FastAPI application entrypoint and composition root."""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from src.api.v1 import auth as auth_router
from src.api.v1 import conversations as conversations_router
from src.api.v1 import files as files_router
from src.api.v1 import messages as messages_router
from src.api.v1 import mfa as mfa_router
from src.api.v1 import oidc as oidc_router
from src.api.v1 import saml as saml_router
from src.api.v1 import users as users_router
from src.api.ws import realtime as realtime_router
from src.core.config import get_settings
from src.core.error_handling import register_exception_handlers
from src.core.logging import configure_logging
from src.core.rate_limit import limiter, rate_limit_exceeded_handler
from src.models import (  # noqa: F401
    conversation,
    email_verification_token,
    external_identity_link,
    file_attachment,
    identity_key,
    message,
    mfa_factor,
    role,
    session,
    user,
)
from src.schemas.base import ErrorResponse
from src.services.errors import AuthError
from src.services.file_errors import FileError
from src.services.messaging_errors import MessagingError
from src.services.user_errors import UserServiceError

configure_logging()

app = FastAPI(title="VAYUNX Chat Application API", version="0.1.0")

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
# slowapi's handler signature (Request, RateLimitExceeded) is narrower than
# Starlette's generic (Request, Exception) handler type — safe at runtime,
# a known typing friction point between the two libraries.
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)  # type: ignore[arg-type]


async def _auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    # Map every auth-domain error to the shared structured shape (FR-022).
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error_code=exc.error_code, message=exc.message).model_dump(),
    )


app.add_exception_handler(AuthError, _auth_error_handler)  # type: ignore[arg-type]


async def _messaging_error_handler(request: Request, exc: MessagingError) -> JSONResponse:
    # Same shared structured shape as auth errors (FR-022).
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error_code=exc.error_code, message=exc.message).model_dump(),
    )


app.add_exception_handler(MessagingError, _messaging_error_handler)  # type: ignore[arg-type]


async def _user_service_error_handler(request: Request, exc: UserServiceError) -> JSONResponse:
    # Same shared structured shape as auth/messaging errors (FR-022).
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error_code=exc.error_code, message=exc.message).model_dump(),
    )


app.add_exception_handler(UserServiceError, _user_service_error_handler)  # type: ignore[arg-type]


async def _file_error_handler(request: Request, exc: FileError) -> JSONResponse:
    # Same shared structured shape as auth/messaging errors (FR-022).
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error_code=exc.error_code, message=exc.message).model_dump(),
    )


app.add_exception_handler(FileError, _file_error_handler)  # type: ignore[arg-type]
register_exception_handlers(app)

app.include_router(auth_router.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(mfa_router.router, prefix="/api/v1/auth", tags=["auth", "mfa"])
app.include_router(oidc_router.router, prefix="/api/v1/auth", tags=["auth", "oidc"])
app.include_router(saml_router.router, prefix="/api/v1/auth", tags=["auth", "saml"])
app.include_router(users_router.router, prefix="/api/v1", tags=["users"])
app.include_router(conversations_router.router, prefix="/api/v1", tags=["conversations"])
app.include_router(messages_router.router, prefix="/api/v1", tags=["messages"])
app.include_router(files_router.router, prefix="/api/v1", tags=["files"])
app.include_router(realtime_router.router, tags=["realtime"])


@app.get("/api/v1/healthz", tags=["health"])
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
