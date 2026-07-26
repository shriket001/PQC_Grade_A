"""Crypto validation tests for every Grade-A provider (Constitution Principle VIII).

Confirms correct algorithm behavior, correct key sizes, and no silent
fallback to a weaker primitive. These test the provider classes directly
(not the factory's config/key-file wiring, which is covered by integration
tests once endpoints exist).
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.crypto.providers.ciphers import AesGcmFileCipher, AesGcmMessageCipher
from src.crypto.providers.digest_provider import Sha3_256DigestProvider
from src.crypto.providers.identity_key_provider import MLDSA65IdentityKeyProvider
from src.crypto.providers.kdf import HKDFSha3256KeyDerivationFunction
from src.crypto.providers.key_exchange_provider import MLKEM768KeyExchangeProvider
from src.crypto.providers.password_hasher import Argon2idPasswordHasher
from src.crypto.providers.token_signer import Ed25519TokenSigner


class TestArgon2idPasswordHasher:
    def test_hash_is_not_plaintext_and_uses_argon2id(self) -> None:
        hasher = Argon2idPasswordHasher()
        hashed = hasher.hash("correct horse battery staple")
        assert "correct horse battery staple" not in hashed
        assert hashed.startswith("$argon2id$")

    def test_verify_accepts_correct_password(self) -> None:
        hasher = Argon2idPasswordHasher()
        hashed = hasher.hash("s3cret-passphrase")
        assert hasher.verify("s3cret-passphrase", hashed) is True

    def test_verify_rejects_incorrect_password(self) -> None:
        hasher = Argon2idPasswordHasher()
        hashed = hasher.hash("s3cret-passphrase")
        assert hasher.verify("wrong-passphrase", hashed) is False


class TestEd25519TokenSigner:
    def _make_signer(self) -> Ed25519TokenSigner:
        private_key = Ed25519PrivateKey.generate()
        return Ed25519TokenSigner(private_key, private_key.public_key())

    def test_sign_and_verify_round_trip(self) -> None:
        signer = self._make_signer()
        payload = b"header.claims"
        signature = signer.sign(payload)
        assert signer.verify(payload, signature) is True

    def test_verify_rejects_tampered_payload(self) -> None:
        signer = self._make_signer()
        signature = signer.sign(b"original.claims")
        assert signer.verify(b"tampered.claims", signature) is False

    def test_verify_rejects_signature_from_a_different_key(self) -> None:
        signer_a = self._make_signer()
        signer_b = self._make_signer()
        payload = b"header.claims"
        signature = signer_a.sign(payload)
        assert signer_b.verify(payload, signature) is False


class TestMLDSA65IdentityKeyProvider:
    def test_keypair_sizes_match_ml_dsa_65_spec(self) -> None:
        provider = MLDSA65IdentityKeyProvider()
        public_key, private_key = provider.generate_keypair()
        # ML-DSA-65 (FIPS 204): public key 1952 bytes, secret key 4032 bytes.
        assert len(public_key) == 1952
        assert len(private_key) == 4032

    def test_sign_and_verify_round_trip(self) -> None:
        provider = MLDSA65IdentityKeyProvider()
        public_key, private_key = provider.generate_keypair()
        message = b"authenticated chat message"
        signature = provider.sign(private_key, message)
        assert provider.verify(public_key, message, signature) is True

    def test_verify_rejects_tampered_message(self) -> None:
        provider = MLDSA65IdentityKeyProvider()
        public_key, private_key = provider.generate_keypair()
        signature = provider.sign(private_key, b"original message")
        assert provider.verify(public_key, b"tampered message", signature) is False


class TestMLKEM768KeyExchangeProvider:
    def test_keypair_sizes_match_ml_kem_768_spec(self) -> None:
        provider = MLKEM768KeyExchangeProvider()
        public_key, private_key = provider.generate_keypair()
        # ML-KEM-768 (FIPS 203): public key 1184 bytes, secret key 2400 bytes.
        assert len(public_key) == 1184
        assert len(private_key) == 2400

    def test_encapsulate_decapsulate_produce_matching_shared_secret(self) -> None:
        provider = MLKEM768KeyExchangeProvider()
        public_key, private_key = provider.generate_keypair()
        ciphertext, shared_secret_sender = provider.encapsulate(public_key)
        shared_secret_receiver = provider.decapsulate(private_key, ciphertext)
        assert shared_secret_sender == shared_secret_receiver
        assert len(shared_secret_sender) == 32


class TestHKDFSha3256KeyDerivationFunction:
    def test_derives_requested_length(self) -> None:
        kdf = HKDFSha3256KeyDerivationFunction()
        derived = kdf.derive(b"shared-secret-material", info=b"message-key", length=32)
        assert len(derived) == 32

    def test_different_info_produces_different_keys(self) -> None:
        kdf = HKDFSha3256KeyDerivationFunction()
        secret = b"shared-secret-material"
        key_a = kdf.derive(secret, info=b"message-key", length=32)
        key_b = kdf.derive(secret, info=b"file-key", length=32)
        assert key_a != key_b


class TestAesGcmCiphers:
    @pytest.mark.parametrize(
        "cipher_cls", [AesGcmMessageCipher, AesGcmFileCipher]
    )
    def test_encrypt_decrypt_round_trip(self, cipher_cls) -> None:
        cipher = cipher_cls()
        key = b"0" * 32
        plaintext = b"the quick brown fox"
        ciphertext, nonce = cipher.encrypt(key, plaintext)
        assert ciphertext != plaintext
        assert len(nonce) == 12
        assert cipher.decrypt(key, ciphertext, nonce) == plaintext

    @pytest.mark.parametrize(
        "cipher_cls", [AesGcmMessageCipher, AesGcmFileCipher]
    )
    def test_nonce_is_unique_per_call(self, cipher_cls) -> None:
        cipher = cipher_cls()
        key = b"0" * 32
        _, nonce_1 = cipher.encrypt(key, b"message one")
        _, nonce_2 = cipher.encrypt(key, b"message two")
        assert nonce_1 != nonce_2

    @pytest.mark.parametrize(
        "cipher_cls", [AesGcmMessageCipher, AesGcmFileCipher]
    )
    def test_tampered_ciphertext_is_rejected(self, cipher_cls) -> None:
        from cryptography.exceptions import InvalidTag

        cipher = cipher_cls()
        key = b"0" * 32
        ciphertext, nonce = cipher.encrypt(key, b"authentic content")
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with pytest.raises(InvalidTag):
            cipher.decrypt(key, tampered, nonce)


class TestSha3_256DigestProvider:
    def test_digest_length_is_256_bits(self) -> None:
        digest = Sha3_256DigestProvider().digest(b"integrity-checked content")
        assert len(digest) == 32

    def test_digest_is_deterministic(self) -> None:
        provider = Sha3_256DigestProvider()
        assert provider.digest(b"same input") == provider.digest(b"same input")

    def test_different_input_produces_different_digest(self) -> None:
        provider = Sha3_256DigestProvider()
        assert provider.digest(b"input a") != provider.digest(b"input b")
