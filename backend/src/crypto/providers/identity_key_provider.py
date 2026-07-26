"""Grade A: ML-DSA-65 identity keys (post-quantum digital signatures, FIPS 204).

Implemented via `liboqs-python`. Primarily exercised client-side (spec
FR-051) and in crypto validation tests; the backend never generates or
holds a user's private identity key in production code paths.
"""

import oqs

from src.crypto.interfaces import IdentityKeyProvider

_ALGORITHM = "ML-DSA-65"


class MLDSA65IdentityKeyProvider(IdentityKeyProvider):
    def generate_keypair(self) -> tuple[bytes, bytes]:
        with oqs.Signature(_ALGORITHM) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
            return public_key, private_key

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        with oqs.Signature(_ALGORITHM, private_key) as signer:
            return bytes(signer.sign(message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(_ALGORITHM) as verifier:
            return bool(verifier.verify(message, signature, public_key))
