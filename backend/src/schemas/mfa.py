"""MFA/TOTP request/response DTOs (FR-009)."""

from pydantic import ConfigDict, Field, model_validator

from src.schemas.base import BaseSchema

# 6-digit numeric TOTP code (RFC 6238 default digit count).
_TOTP_CODE_PATTERN = r"^\d{6}$"


class MfaEnrollResponse(BaseSchema):
    # `otpauth://` URI an authenticator app scans directly (rendered as a QR
    # code client-side); `secret` is the same shared secret in base32, shown
    # once for manual entry. Neither is retrievable again after this response.
    otpauth_uri: str
    secret: str


class MfaConfirmRequest(BaseSchema):
    totp_code: str = Field(pattern=_TOTP_CODE_PATTERN)


class MfaConfirmResponse(BaseSchema):
    enabled: bool


class MfaDisableRequest(BaseSchema):
    # Passwords deliberately are NOT whitespace-stripped (same rationale as
    # `LoginRequest` in schemas/auth.py) — a password may legitimately contain
    # leading/trailing characters, and stripping would silently change it.
    model_config = ConfigDict(str_strip_whitespace=False, extra="forbid", populate_by_name=True)

    # Exactly one of these proves the caller still controls the account
    # (rest-api.md: "current password or code").
    password: str | None = Field(default=None, min_length=1, max_length=1024)
    totp_code: str | None = Field(default=None, pattern=_TOTP_CODE_PATTERN)

    @model_validator(mode="after")
    def _exactly_one_proof(self) -> "MfaDisableRequest":
        if (self.password is None) == (self.totp_code is None):
            raise ValueError("provide exactly one of password or totp_code")
        return self
