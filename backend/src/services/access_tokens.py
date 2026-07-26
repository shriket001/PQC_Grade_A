"""Access token (compact JWS) mint/decode over the abstract TokenSigner.

Stays entirely on the `TokenSigner` interface (Constitution Principle I / §2.3)
— this module never imports Ed25519 or any concrete signer. The token format is
a compact JWS:  base64url(header).base64url(payload).base64url(signature),
where `signature = signer.sign(header_b64.payload_b64)`.

Claims:
  - sub: user id (str UUID)
  - sid: session id (str UUID)
  - iat / exp: unix seconds

Short-lived per `Settings.jwt_access_token_ttl_seconds`. Expiry is verified
here so every consumer of `decode` gets only a currently-valid token.
"""

import base64
import json
import time
from dataclasses import dataclass
from uuid import UUID

from src.crypto.interfaces import TokenSigner

_HEADER = {"alg": "EdDSA", "typ": "JWT"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


@dataclass(frozen=True)
class AccessTokenClaims:
    user_id: UUID
    session_id: UUID
    expires_at: int  # unix seconds


class InvalidAccessTokenError(Exception):
    """Internal signal that a presented token is malformed/unsigned/expired.

    Mapped to the client-facing `UnauthenticatedError` by the auth dependency.
    """


def mint(token_signer: TokenSigner, *, user_id: UUID, session_id: UUID, ttl_seconds: int) -> str:
    now = int(time.time())
    header_b64 = _b64url(json.dumps(_HEADER, separators=(",", ":"), sort_keys=True).encode())
    payload_b64 = _b64url(
        json.dumps(
            {"sub": str(user_id), "sid": str(session_id), "iat": now, "exp": now + ttl_seconds},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = token_signer.sign(signing_input)
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


def decode(token_signer: TokenSigner, token: str) -> AccessTokenClaims:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as err:
        raise InvalidAccessTokenError("malformed token") from err
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        signature = _b64url_decode(sig_b64)
    except Exception as err:  # noqa: BLE001 — any decode failure is a bad token
        raise InvalidAccessTokenError("bad signature encoding") from err
    if not token_signer.verify(signing_input, signature):
        raise InvalidAccessTokenError("bad signature")
    try:
        payload = json.loads(_b64url_decode(payload_b64))
        claims = AccessTokenClaims(
            user_id=UUID(str(payload["sub"])),
            session_id=UUID(str(payload["sid"])),
            expires_at=int(payload["exp"]),
        )
    except Exception as err:  # noqa: BLE001 — any parse failure is a bad token
        raise InvalidAccessTokenError("bad payload") from err
    if int(time.time()) >= claims.expires_at:
        raise InvalidAccessTokenError("expired")
    return claims
