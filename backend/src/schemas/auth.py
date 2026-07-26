"""Auth request/response DTOs (US1 / Phase 4).

Auth requests deliberately do NOT strip whitespace: passwords may legitimately
contain leading/trailing characters and stripping them would silently change
the user's secret. The `email` field is normalized (stripped + lowercased) in a
validator instead.
"""

from datetime import datetime
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator

from src.schemas.base import BaseSchema

# Pragmatic email shape check (no external `email-validator` dependency).
_EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

# Username handle: letters, digits, underscore; 3–32 chars. This is the
# application's unique public identifier (FR-052). Mixed-case input is allowed
# and normalized to lowercase in the validator below so uniqueness is
# case-insensitive.
_USERNAME_PATTERN = r"^[a-zA-Z0-9_]{3,32}$"


class _AuthRequestSchema(BaseSchema):
    """Base for auth request DTOs: forbid extras, but do NOT strip whitespace."""

    model_config = ConfigDict(
        str_strip_whitespace=False,
        extra="forbid",
        populate_by_name=True,
    )


class RegisterRequest(_AuthRequestSchema):
    email: str = Field(pattern=_EMAIL_PATTERN, max_length=320)
    password: str = Field(min_length=1, max_length=1024)  # complexity enforced in the service
    username: str = Field(pattern=_USERNAME_PATTERN, max_length=32)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        # Case-insensitive uniqueness: store the canonical lowercase form.
        return value.strip().lower()


class VerifyEmailRequest(_AuthRequestSchema):
    verification_token: str = Field(min_length=1, max_length=256)


class LoginRequest(_AuthRequestSchema):
    email: str = Field(pattern=_EMAIL_PATTERN, max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    device_context: str | None = Field(default=None, max_length=255)
    # Required only if the account has TOTP MFA enabled (FR-009) — omitted (or
    # wrong) on such an account fails with `mfa_required`/`invalid_mfa_code`.
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class TokenResponse(BaseSchema):
    # The refresh token is NEVER in this body — it travels solely as an
    # HttpOnly cookie the browser sends automatically (see api/v1/auth.py),
    # so no client-side JS ever holds it (FR-005/US10).
    access_token: str
    token_type: str = "Bearer"
    expires_at: datetime


class RegisterResponse(BaseSchema):
    user_id: UUID
    username: str
    status: str  # "unverified" until email verification completes


class VerifyEmailResponse(BaseSchema):
    verified: bool


class SessionResponse(BaseSchema):
    """One entry in `GET /auth/sessions` (FR-006/US10) — a device/login instance."""

    session_id: UUID
    device_context: str | None
    created_at: datetime
    # True for the session the CURRENT request is authenticated under, so the
    # UI can label it ("This device") and withhold a revoke action for it —
    # revoking your own live session is what /auth/logout is for.
    current: bool
