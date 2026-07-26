"""Redis-backed rate limiting (FR-014).

Exposes a shared `slowapi` `Limiter` backed by Redis storage. Endpoints wire
their own threshold via the `@limiter.limit("N/minute")` decorator where
needed (login: T045, password-reset request / MFA verification: T097/T113)
rather than applying one global rule.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from src.core.config import get_settings

limiter = Limiter(key_func=get_remote_address, storage_uri=get_settings().redis_url)


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={
            "error_code": "rate_limited",
            "message": "Too many requests. Please try again later.",
        },
    )
