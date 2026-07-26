"""Grade A: AES-256-GCM AEAD for message and file content.

A fresh, cryptographically random 96-bit nonce is generated for every
encrypt call (Constitution: Secure Random / no reused nonces).
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.crypto.interfaces import FileCipher, MessageCipher

_NONCE_LENGTH_BYTES = 12


def _encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(_NONCE_LENGTH_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return ciphertext, nonce


def _decrypt(key: bytes, ciphertext: bytes, nonce: bytes, associated_data: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


class AesGcmMessageCipher(MessageCipher):
    def encrypt(
        self, key: bytes, plaintext: bytes, *, associated_data: bytes = b""
    ) -> tuple[bytes, bytes]:
        return _encrypt(key, plaintext, associated_data)

    def decrypt(
        self, key: bytes, ciphertext: bytes, nonce: bytes, *, associated_data: bytes = b""
    ) -> bytes:
        return _decrypt(key, ciphertext, nonce, associated_data)


class AesGcmFileCipher(FileCipher):
    def encrypt(
        self, key: bytes, plaintext: bytes, *, associated_data: bytes = b""
    ) -> tuple[bytes, bytes]:
        return _encrypt(key, plaintext, associated_data)

    def decrypt(
        self, key: bytes, ciphertext: bytes, nonce: bytes, *, associated_data: bytes = b""
    ) -> bytes:
        return _decrypt(key, ciphertext, nonce, associated_data)
