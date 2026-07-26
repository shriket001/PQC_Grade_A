"""User-directory DTOs (US2 user discovery — FR-052/FR-053).

`UserSummaryResponse` is the public, directory-facing projection: it exposes
the unique `username` handle plus the friendly `display_name`, but **never the
email** — email is PII and must not be enumerable through the discovery
surface. `UserProfileResponse` is the self-scoped `/users/me` projection and
additionally includes email + verification status.
"""

from datetime import datetime
from uuid import UUID

from src.schemas.base import BaseSchema


class UserSummaryResponse(BaseSchema):
    id: UUID
    username: str
    display_name: str


class UserProfileResponse(BaseSchema):
    id: UUID
    username: str
    display_name: str
    email: str
    email_verified: bool
    created_at: datetime
    # Whether this account currently has an active TOTP factor (FR-009) — lets
    # the settings UI show "enable MFA" vs. "disable MFA" without a separate
    # status endpoint.
    mfa_enabled: bool
