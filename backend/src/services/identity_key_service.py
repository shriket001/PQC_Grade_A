"""IdentityKeyService — public-key directory + rotation orchestration (US2).

The server is a *public-key directory*: it stores only public ML-DSA-65 signing
keys and ML-KEM-768 KEM keys, never private keys (research.md #1, FR-043/FR-044).
Rotation (FR-049) is attested by a signature from the outgoing private key over
the new public material; the server verifies that attestation with the outgoing
*public* signing key before accepting the rotation — it never holds the private
key that produced it. All crypto goes through the `IdentityKeyProvider`
interface (Constitution §2.3); this service never imports a concrete lib.
"""

import base64
from uuid import UUID

from src.crypto.interfaces import IdentityKeyProvider
from src.models.identity_key import IdentityKeyRecord
from src.repositories.identity_key_repository import IdentityKeyRepository
from src.services.messaging_errors import InvalidRotationAttestationError


def _decode_b64(value: str) -> bytes:
    # Validate=True rejects silently-truncated/whitespace-laden material so a
    # malformed key never silently round-trips into a row.
    return base64.b64decode(value, validate=True)


def _opt_b64(value: str | None) -> bytes | None:
    # Optional base64 decode for the FR-054 wrapped material: None stays None so
    # legacy rows / non-recovering publishes store no wrapped blob.
    if value is None:
        return None
    return _decode_b64(value)


class IdentityKeyService:
    def __init__(
        self,
        identity_key_repo: IdentityKeyRepository,
        identity_key_provider: IdentityKeyProvider,
    ) -> None:
        self._repo = identity_key_repo
        self._provider = identity_key_provider

    async def publish(
        self,
        *,
        user_id: UUID,
        device_label: str,
        public_signing_key_b64: str,
        public_kem_key_b64: str,
        wrapped_signing_private_key_b64: str | None = None,
        wrapped_kem_private_key_b64: str | None = None,
        wrap_nonce_b64: str | None = None,
        wrap_kdf_salt_b64: str | None = None,
        wrap_kdf_params: str | None = None,
        wrap_alg: str | None = None,
    ) -> IdentityKeyRecord:
        """Publish the user's first (or new-device) public key pair.

        First publish sets key_version = 1; an additional device publish gets
        the next version number without superseding existing device keys (a user
        may hold several concurrently active keys, one per device).

        FR-054: when the optional wrapped private-key blobs + wrap parameters are
        supplied, they are stored verbatim (opaque to the server) so the identity
        can be recovered on another device. The wrapped fields must be supplied
        as a complete set (all-or-none) — enforced at the route layer.
        """
        active = await self._repo.list_active_for_user(user_id)
        next_version = (active[0].key_version + 1) if active else 1
        record = IdentityKeyRecord(
            user_id=user_id,
            device_label=device_label,
            public_signing_key=_decode_b64(public_signing_key_b64),
            public_kem_key=_decode_b64(public_kem_key_b64),
            key_version=next_version,
            wrapped_signing_private_key=_opt_b64(wrapped_signing_private_key_b64),
            wrapped_kem_private_key=_opt_b64(wrapped_kem_private_key_b64),
            wrap_nonce=_opt_b64(wrap_nonce_b64),
            wrap_kdf_salt=_opt_b64(wrap_kdf_salt_b64),
            wrap_kdf_params=wrap_kdf_params,
            wrap_alg=wrap_alg,
        )
        return await self._repo.add(record)

    async def list_active(self, user_id: UUID) -> list[IdentityKeyRecord]:
        return await self._repo.list_active_for_user(user_id)

    async def get_active_with_wrapped(self, user_id: UUID) -> IdentityKeyRecord | None:
        """Auth-scoped fetch of the user's active key, INCLUDING wrapped private
        material (FR-054). Only the owner may call this — the route is
        `GET /users/me/identity-key`, authenticated."""
        return await self._repo.get_active_for_user(user_id)

    async def get_active_for_user(
        self, user_id: UUID, *, key_version: int | None = None
    ) -> IdentityKeyRecord | None:
        return await self._repo.get_active_for_user(user_id, key_version=key_version)

    async def rotate(
        self,
        *,
        user_id: UUID,
        new_public_signing_key_b64: str,
        new_public_kem_key_b64: str,
        rotation_attestation_b64: str,
        wrapped_signing_private_key_b64: str | None = None,
        wrapped_kem_private_key_b64: str | None = None,
        wrap_nonce_b64: str | None = None,
        wrap_kdf_salt_b64: str | None = None,
        wrap_kdf_params: str | None = None,
        wrap_alg: str | None = None,
    ) -> IdentityKeyRecord:
        """Rotate the user's current active key (FR-049).

        Verifies the rotation attestation with the *outgoing* public signing key
        before superseding it: the attestation is a signature over the
        concatenation of the two new public keys, proving the new key pair is
        genuinely the successor of the old one. The outgoing record is marked
        superseded (retained, not deleted) so messages signed by it stay
        verifiable; the new record carries the stored attestation and the next
        version number.

        FR-054: the rotated key may carry re-wrapped private material under the
        (unchanged) password-derived key, stored verbatim.
        """
        outgoing = await self._repo.get_active_for_user(user_id)
        if outgoing is None:
            # Rotation requires an existing key to rotate from; a first-time
            # publish is a separate operation and must not pretend to rotate.
            raise InvalidRotationAttestationError("no active key to rotate from")

        new_signing = _decode_b64(new_public_signing_key_b64)
        new_kem = _decode_b64(new_public_kem_key_b64)
        attestation = _decode_b64(rotation_attestation_b64)
        signed_message = new_signing + new_kem
        if not self._provider.verify(outgoing.public_signing_key, signed_message, attestation):
            raise InvalidRotationAttestationError()

        await self._repo.mark_superseded(outgoing)
        record = IdentityKeyRecord(
            user_id=user_id,
            device_label=outgoing.device_label,
            public_signing_key=new_signing,
            public_kem_key=new_kem,
            key_version=outgoing.key_version + 1,
            rotation_attestation=attestation,
            wrapped_signing_private_key=_opt_b64(wrapped_signing_private_key_b64),
            wrapped_kem_private_key=_opt_b64(wrapped_kem_private_key_b64),
            wrap_nonce=_opt_b64(wrap_nonce_b64),
            wrap_kdf_salt=_opt_b64(wrap_kdf_salt_b64),
            wrap_kdf_params=wrap_kdf_params,
            wrap_alg=wrap_alg,
        )
        return await self._repo.add(record)
