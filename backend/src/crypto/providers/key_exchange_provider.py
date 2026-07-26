"""Grade A: ML-KEM-768 key exchange (post-quantum KEM, FIPS 203).

Implemented via `liboqs-python`. Primarily exercised client-side (spec
FR-051) and in crypto validation tests; the backend never holds a user's
private key-exchange key in production code paths.
"""

import oqs

from src.crypto.interfaces import KeyExchangeProvider

_ALGORITHM = "ML-KEM-768"


class MLKEM768KeyExchangeProvider(KeyExchangeProvider):
    def generate_keypair(self) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(_ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            return public_key, private_key

    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(peer_public_key)
            return ciphertext, shared_secret

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        with oqs.KeyEncapsulation(_ALGORITHM, private_key) as kem:
            return bytes(kem.decap_secret(ciphertext))
