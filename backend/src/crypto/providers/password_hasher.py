"""Grade A: Argon2id password hashing."""

from argon2 import PasswordHasher as _Argon2PasswordHasher
from argon2.exceptions import VerifyMismatchError

from src.crypto.interfaces import PasswordHasher


class Argon2idPasswordHasher(PasswordHasher):
    def __init__(self) -> None:
        # argon2-cffi defaults to the Argon2id variant.
        self._hasher = _Argon2PasswordHasher()

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password: str, hashed: str) -> bool:
        try:
            return self._hasher.verify(hashed, password)
        except VerifyMismatchError:
            return False
