"""Grade A: SHA3-256 hashing for integrity checks."""

from cryptography.hazmat.primitives import hashes

from src.crypto.interfaces import DigestProvider


class Sha3_256DigestProvider(DigestProvider):
    def digest(self, data: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA3_256())
        digest.update(data)
        return digest.finalize()
