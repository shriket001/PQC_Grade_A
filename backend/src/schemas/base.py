"""Shared Pydantic v2 DTO conventions.

Every request/response DTO in the application extends `BaseSchema`. No
endpoint accepts or returns a bare dict (Constitution Principle VII).
"""

from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
    """Base for all request/response DTOs: strict, immutable-by-default field naming."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
        populate_by_name=True,
    )


class ErrorResponse(BaseSchema):
    """Structured, safe client-facing error shape (Constitution Principle VI/FR-022)."""

    error_code: str
    message: str
