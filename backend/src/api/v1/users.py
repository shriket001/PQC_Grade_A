"""User-facing endpoints — username directory, profile, and identity keys (US2).

The server acts as a *public-key + username directory*: any authenticated user
may resolve another user by their unique username handle (FR-053) and fetch
their active public keys (needed to encapsulate/verify messages to them).
Self-scoped profile + key management live under `/users/me/...`. All bodies are
strict Pydantic DTOs (Constitution Principle VII); the directory projection
(`UserSummaryResponse`) never exposes email (FR-022).
"""

import base64
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.core.config import get_settings
from src.core.dependencies import (
    AuthContext,
    get_current_session,
    get_identity_key_service,
    get_mfa_factor_repository,
    get_user_service,
)
from src.core.rate_limit import limiter
from src.models.identity_key import IdentityKeyRecord
from src.models.user import User
from src.repositories.mfa_factor_repository import MfaFactorRepository
from src.schemas.messaging import (
    IdentityKeyResponse,
    PublicIdentityKeyResponse,
    PublishIdentityKeyRequest,
    RotateIdentityKeyRequest,
)
from src.schemas.user import UserProfileResponse, UserSummaryResponse
from src.services.identity_key_service import IdentityKeyService
from src.services.user_service import UserService

router = APIRouter()

_settings = get_settings()
_SEARCH_LIMIT = f"{_settings.rate_limit_user_search_per_minute}/minute"


def _b64(value: bytes | None) -> str | None:
    if value is None:
        return None
    return base64.b64encode(value).decode("ascii")


def _to_public_key_response(record: IdentityKeyRecord) -> PublicIdentityKeyResponse:
    # Directory projection: public material only — wrapped private keys are
    # deliberately omitted (FR-054 security boundary).
    return PublicIdentityKeyResponse(
        id=record.id,
        user_id=record.user_id,
        device_label=record.device_label,
        public_signing_key=base64.b64encode(record.public_signing_key).decode("ascii"),
        public_kem_key=base64.b64encode(record.public_kem_key).decode("ascii"),
        key_version=record.key_version,
        created_at=record.created_at,
        superseded_at=record.superseded_at,
    )


def _to_full_key_response(record: IdentityKeyRecord) -> IdentityKeyResponse:
    # Auth-scoped projection for the owner: includes wrapped private material.
    return IdentityKeyResponse(
        id=record.id,
        user_id=record.user_id,
        device_label=record.device_label,
        public_signing_key=base64.b64encode(record.public_signing_key).decode("ascii"),
        public_kem_key=base64.b64encode(record.public_kem_key).decode("ascii"),
        key_version=record.key_version,
        created_at=record.created_at,
        superseded_at=record.superseded_at,
        wrapped_signing_private_key=_b64(record.wrapped_signing_private_key),
        wrapped_kem_private_key=_b64(record.wrapped_kem_private_key),
        wrap_nonce=_b64(record.wrap_nonce),
        wrap_kdf_salt=_b64(record.wrap_kdf_salt),
        wrap_kdf_params=record.wrap_kdf_params,
        wrap_alg=record.wrap_alg,
    )


def _wrapped_fields(
    body: PublishIdentityKeyRequest | RotateIdentityKeyRequest,
) -> dict[str, str | None]:
    # FR-054: the wrapped material must be supplied as a complete set
    # (all-or-none) so a half-wrapped record can never be persisted.
    fields = {
        "wrapped_signing_private_key_b64": body.wrapped_signing_private_key,
        "wrapped_kem_private_key_b64": body.wrapped_kem_private_key,
        "wrap_nonce_b64": body.wrap_nonce,
        "wrap_kdf_salt_b64": body.wrap_kdf_salt,
        "wrap_kdf_params": body.wrap_kdf_params,
        "wrap_alg": body.wrap_alg,
    }
    present = [v for v in fields.values() if v is not None]
    if 0 < len(present) < len(fields):
        # Half-wrapped records must never be persisted (FR-054 all-or-none rule).
        raise HTTPException(
            status_code=400,
            detail="wrapped identity fields must be supplied as a complete set",
        )
    return fields


def _to_summary(user: User) -> UserSummaryResponse:
    # The directory projection: unique handle + friendly name, never email.
    return UserSummaryResponse(id=user.id, username=user.username, display_name=user.display_name)


# `/users/me/...` and `/users/search` are declared before the `{user_id}` route
# so the literal segments "me"/"search" are matched without being parsed as UUIDs.
@router.post("/users/me/identity-keys", response_model=IdentityKeyResponse, status_code=201)
async def publish_identity_key(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    body: PublishIdentityKeyRequest,
    service: Annotated[IdentityKeyService, Depends(get_identity_key_service)],
) -> IdentityKeyResponse:
    wrapped = _wrapped_fields(body)
    record = await service.publish(
        user_id=ctx.user.id,
        device_label=body.device_label,
        public_signing_key_b64=body.public_signing_key,
        public_kem_key_b64=body.public_kem_key,
        **wrapped,
    )
    return _to_full_key_response(record)


@router.post("/users/me/identity-keys/rotate", response_model=IdentityKeyResponse)
async def rotate_identity_key(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    body: RotateIdentityKeyRequest,
    service: Annotated[IdentityKeyService, Depends(get_identity_key_service)],
) -> IdentityKeyResponse:
    wrapped = _wrapped_fields(body)
    record = await service.rotate(
        user_id=ctx.user.id,
        new_public_signing_key_b64=body.new_public_signing_key,
        new_public_kem_key_b64=body.new_public_kem_key,
        rotation_attestation_b64=body.rotation_attestation,
        **wrapped,
    )
    return _to_full_key_response(record)


@router.get("/users/me/identity-key", response_model=IdentityKeyResponse)
async def get_my_identity_key(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    service: Annotated[IdentityKeyService, Depends(get_identity_key_service)],
) -> IdentityKeyResponse:
    # Auth-scoped fetch of the caller's active identity, INCLUDING wrapped
    # private material (FR-054). 404 when the caller has published no key yet
    # (first login / new account) so the client knows to generate + wrap + publish.
    # Declared before `/{user_id}` routes so "me" is matched literally, not as a UUID.
    record = await service.get_active_with_wrapped(ctx.user.id)
    if record is None:
        raise HTTPException(status_code=404, detail="no active identity key")
    return _to_full_key_response(record)


@router.get("/users/me", response_model=UserProfileResponse)
async def get_my_profile(
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    service: Annotated[UserService, Depends(get_user_service)],
    mfa_repo: Annotated[MfaFactorRepository, Depends(get_mfa_factor_repository)],
) -> UserProfileResponse:
    # The auth context guarantees the user exists; get_profile returns it.
    user = await service.get_profile(ctx.user.id)
    active_factor = await mfa_repo.get_active_for_user(user.id)
    return UserProfileResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        email_verified=user.email_verified,
        created_at=user.created_at,
        mfa_enabled=active_factor is not None,
    )


@router.get("/users/search", response_model=list[UserSummaryResponse])
@limiter.limit(_SEARCH_LIMIT)
async def search_users(
    request: Request,
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    service: Annotated[UserService, Depends(get_user_service)],
    q: str = Query(min_length=2, max_length=32, description="Username prefix to search for"),
) -> list[UserSummaryResponse]:
    # FR-053: resolve users by username PREFIX (case-insensitive), for an
    # autocomplete/picker UX. Capped to a small result count server-side and
    # rate-limited here so this stays a bounded lookup aid, not a bulk
    # account-directory dump — the `min_length=2` floor keeps a single
    # keystroke from scanning the whole table.
    users = await service.search_by_username(q)
    return [_to_summary(u) for u in users]


@router.get("/users/{user_id}", response_model=UserSummaryResponse)
async def get_user_summary(
    user_id: UUID,
    ctx: Annotated[AuthContext, Depends(get_current_session)],
    service: Annotated[UserService, Depends(get_user_service)],
) -> UserSummaryResponse:
    # Public summary by id (no email) — used to label conversation peers by
    # username in the client. `ctx` enforces authentication; any authenticated
    # user may resolve any user's public handle.
    user = await service.get_summary(user_id)
    return _to_summary(user)


@router.get("/users/{user_id}/identity-keys", response_model=list[PublicIdentityKeyResponse])
async def list_identity_keys(
    user_id: UUID,
    service: Annotated[IdentityKeyService, Depends(get_identity_key_service)],
) -> list[PublicIdentityKeyResponse]:
    # Public directory lookup — any authenticated user may read another's
    # active public keys (needed to encrypt/verify messages to them). Wrapped
    # private material is deliberately stripped (FR-054 security boundary).
    keys = await service.list_active(user_id)
    return [_to_public_key_response(k) for k in keys]
