"""Grade A: HKDF-SHA3-256 key derivation."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.crypto.interfaces import KeyDerivationFunction


class HKDFSha3256KeyDerivationFunction(KeyDerivationFunction):
    def derive(self, shared_secret: bytes, *, info: bytes, length: int) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA3_256(), length=length, salt=None, info=info)
        return hkdf.derive(shared_secret)
