"""Global exception handling: safe client-facing responses + structured server-side logging.

At this checkpoint (Foundational phase), unhandled errors are logged via
structlog only. T125 (User Story 11) extends `on_error` to additionally
persist an `ErrorLogEntry` once that model exists — the FastAPI exception
handler wiring here does not change, only what `on_error` does internally.
"""

from typing import Protocol

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from src.core.logging import get_logger
from src.schemas.base import ErrorResponse

logger = get_logger(__name__)


class ErrorSink(Protocol):
    """Persists error records. Swapped for a DB-backed implementation in T125."""

    async def record(self, *, level: str, message: str, context: dict[str, object]) -> None: ...


class LoggingErrorSink:
    async def record(self, *, level: str, message: str, context: dict[str, object]) -> None:
        logger.bind(**context).log(logging_level(level), message)


def logging_level(level: str) -> int:
    import logging

    return {"error": logging.ERROR, "critical": logging.CRITICAL}.get(level, logging.ERROR)


_error_sink: ErrorSink = LoggingErrorSink()


def set_error_sink(sink: ErrorSink) -> None:
    """Allows T125 to install a DB-backed sink without touching this module's wiring."""
    global _error_sink
    _error_sink = sink


async def on_error(request: Request, exc: Exception) -> JSONResponse:
    correlation_id = request.headers.get("x-correlation-id", "unknown")
    await _error_sink.record(
        level="error",
        message=str(exc),
        context={
            "path": request.url.path,
            "method": request.method,
            "correlation_id": correlation_id,
            "exception_type": type(exc).__name__,
        },
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error_code="internal_error",
            message="An unexpected error occurred. Please try again later.",
        ).model_dump(),
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(Exception, on_error)
