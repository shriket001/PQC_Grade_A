"""Crypto validation test for `AesGcmFileCipher` (T073).

This provider is a reference implementation for client-side use/tests
(`interfaces.py`'s `FileCipher` docstring) — the backend never calls it
against real user file content (FR-051). Validates round-trip correctness and
tamper detection, the same guarantees `test_providers.py` validates for the
sibling message cipher.
"""

import os

import pytest
from cryptography.exceptions import InvalidTag

from src.crypto.providers.ciphers import AesGcmFileCipher


class TestAesGcmFileCipher:
    def test_encrypt_decrypt_round_trip(self) -> None:
        cipher = AesGcmFileCipher()
        key = os.urandom(32)
        plaintext = b"\x89PNG\r\n\x1a\n" + os.urandom(4096)  # fake image bytes

        ciphertext, nonce = cipher.encrypt(key, plaintext)
        assert ciphertext != plaintext
        recovered = cipher.decrypt(key, ciphertext, nonce)
        assert recovered == plaintext

    def test_nonce_is_random_per_call(self) -> None:
        cipher = AesGcmFileCipher()
        key = os.urandom(32)
        _, nonce_a = cipher.encrypt(key, b"same plaintext")
        _, nonce_b = cipher.encrypt(key, b"same plaintext")
        assert nonce_a != nonce_b

    def test_associated_data_binds_ciphertext(self) -> None:
        cipher = AesGcmFileCipher()
        key = os.urandom(32)
        ciphertext, nonce = cipher.encrypt(key, b"file bytes", associated_data=b"conversation-1")
        with pytest.raises(InvalidTag):
            cipher.decrypt(key, ciphertext, nonce, associated_data=b"conversation-2")

    def test_tamper_detection(self) -> None:
        cipher = AesGcmFileCipher()
        key = os.urandom(32)
        ciphertext, nonce = cipher.encrypt(key, b"original file content")
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with pytest.raises(InvalidTag):
            cipher.decrypt(key, tampered, nonce)

    def test_wrong_key_fails(self) -> None:
        cipher = AesGcmFileCipher()
        ciphertext, nonce = cipher.encrypt(os.urandom(32), b"secret file")
        with pytest.raises(InvalidTag):
            cipher.decrypt(os.urandom(32), ciphertext, nonce)
