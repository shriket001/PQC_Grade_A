"""Cryptographic isolation boundary (Constitution Principle I).

Every backend module that needs a cryptographic operation depends on these
interfaces only — never on a concrete algorithm library. Swapping this
grade's algorithms for a future grade means replacing the implementations in
`crypto/providers/` and the wiring in `crypto/factory.py`; nothing outside
this package should ever change as a result.

These interfaces cover only what legitimately belongs on the server. Message
and file content encryption/decryption and private identity-key material are
a client-side concern (spec FR-051) — `IdentityKeyProvider`/`KeyExchangeProvider`
here model the server's role as a public-key directory and signer, not as a
holder of private keys or plaintext.
"""

from abc import ABC, abstractmethod


class PasswordHasher(ABC):
    """Hashes and verifies user passwords. Never reversible to the original password."""

    @abstractmethod
    def hash(self, password: str) -> str: ...

    @abstractmethod
    def verify(self, password: str, hashed: str) -> bool: ...


class TokenSigner(ABC):
    """Signs and verifies authentication tokens (e.g. JWT access tokens)."""

    @abstractmethod
    def sign(self, payload: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class IdentityKeyProvider(ABC):
    """Generates/verifies identity key pairs used to authenticate message authorship.

    The server only ever handles public keys and signatures produced by a
    client-held private key; it never generates or stores a private key.
    """

    @abstractmethod
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Returns (public_key, private_key). Only used client-side/in tests."""
        ...

    @abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


class KeyExchangeProvider(ABC):
    """Establishes a shared secret between parties without transmitting it in the clear."""

    @abstractmethod
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Returns (public_key, private_key). Only used client-side/in tests."""
        ...

    @abstractmethod
    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret) for the initiating party."""
        ...

    @abstractmethod
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Returns shared_secret for the receiving party."""
        ...


class KeyDerivationFunction(ABC):
    """Derives working keys from a shared secret. Raw shared secrets are never reused directly."""

    @abstractmethod
    def derive(self, shared_secret: bytes, *, info: bytes, length: int) -> bytes: ...


class MessageCipher(ABC):
    """Encrypts/decrypts message content. Reference implementation for client-side use/tests."""

    @abstractmethod
    def encrypt(
        self, key: bytes, plaintext: bytes, *, associated_data: bytes = b""
    ) -> tuple[bytes, bytes]:
        """Returns (ciphertext, nonce)."""
        ...

    @abstractmethod
    def decrypt(
        self, key: bytes, ciphertext: bytes, nonce: bytes, *, associated_data: bytes = b""
    ) -> bytes: ...


class FileCipher(ABC):
    """Encrypts/decrypts file content. Reference implementation for client-side use/tests."""

    @abstractmethod
    def encrypt(
        self, key: bytes, plaintext: bytes, *, associated_data: bytes = b""
    ) -> tuple[bytes, bytes]:
        """Returns (ciphertext, nonce)."""
        ...

    @abstractmethod
    def decrypt(
        self, key: bytes, ciphertext: bytes, nonce: bytes, *, associated_data: bytes = b""
    ) -> bytes: ...


class DigestProvider(ABC):
    """Cryptographic hashing for integrity checks (not password storage — see PasswordHasher)."""

    @abstractmethod
    def digest(self, data: bytes) -> bytes: ...
