"""Grade A: Ed25519 token signing."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from src.crypto.interfaces import TokenSigner


class Ed25519TokenSigner(TokenSigner):
    def __init__(self, private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey) -> None:
        self._private_key = private_key
        self._public_key = public_key

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(payload)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, payload)
            return True
        except InvalidSignature:
            return False
