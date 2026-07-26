"""Crypto provider factory (Constitution Principle X: the single swap point across grades).

A future grade replaces the concrete providers imported here (and their
constructors below) to change algorithms — no other file in the codebase
needs to change. Algorithm choice is read from configuration
(`Settings.crypto_grade`), never hardcoded into a business-logic branch.
"""

from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from src.core.config import Settings, get_settings
from src.crypto.interfaces import (
    DigestProvider,
    FileCipher,
    IdentityKeyProvider,
    KeyDerivationFunction,
    KeyExchangeProvider,
    MessageCipher,
    PasswordHasher,
    TokenSigner,
)
from src.crypto.providers.ciphers import AesGcmFileCipher, AesGcmMessageCipher
from src.crypto.providers.digest_provider import Sha3_256DigestProvider
from src.crypto.providers.identity_key_provider import MLDSA65IdentityKeyProvider
from src.crypto.providers.kdf import HKDFSha3256KeyDerivationFunction
from src.crypto.providers.key_exchange_provider import MLKEM768KeyExchangeProvider
from src.crypto.providers.password_hasher import Argon2idPasswordHasher
from src.crypto.providers.token_signer import Ed25519TokenSigner

_SUPPORTED_GRADES = {"grade-a"}


def _require_grade_a(settings: Settings) -> None:
    if settings.crypto_grade not in _SUPPORTED_GRADES:
        raise ValueError(
            f"Unsupported crypto_grade '{settings.crypto_grade}' for this codebase. "
            "This grade folder only implements Grade A; a different grade lives in its own folder."
        )


@lru_cache
def get_password_hasher() -> PasswordHasher:
    _require_grade_a(get_settings())
    return Argon2idPasswordHasher()


@lru_cache
def get_token_signer() -> TokenSigner:
    settings = get_settings()
    _require_grade_a(settings)
    with open(settings.jwt_signing_private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    with open(settings.jwt_signing_public_key_path, "rb") as f:
        public_key = load_pem_public_key(f.read())
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Configured JWT signing private key is not Ed25519, as Grade A requires.")
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Configured JWT signing public key is not Ed25519, as Grade A requires.")
    return Ed25519TokenSigner(private_key, public_key)


@lru_cache
def get_identity_key_provider() -> IdentityKeyProvider:
    _require_grade_a(get_settings())
    return MLDSA65IdentityKeyProvider()


@lru_cache
def get_key_exchange_provider() -> KeyExchangeProvider:
    _require_grade_a(get_settings())
    return MLKEM768KeyExchangeProvider()


@lru_cache
def get_key_derivation_function() -> KeyDerivationFunction:
    _require_grade_a(get_settings())
    return HKDFSha3256KeyDerivationFunction()


@lru_cache
def get_message_cipher() -> MessageCipher:
    _require_grade_a(get_settings())
    return AesGcmMessageCipher()


@lru_cache
def get_file_cipher() -> FileCipher:
    _require_grade_a(get_settings())
    return AesGcmFileCipher()


@lru_cache
def get_digest_provider() -> DigestProvider:
    _require_grade_a(get_settings())
    return Sha3_256DigestProvider()
