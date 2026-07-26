"""Unit tests for password complexity validation and Argon2id hashing (T032)."""

import pytest

from src.crypto.factory import get_password_hasher
from src.services import password_policy


class TestPasswordPolicy:
    def test_accepts_a_strong_password(self) -> None:
        password_policy.validate("Sup3rSecretPass!")  # no exception

    def test_rejects_too_short(self) -> None:
        with pytest.raises(password_policy.PasswordPolicyError):
            password_policy.validate("Abcdef1")  # 7 chars

    def test_rejects_missing_lowercase(self) -> None:
        with pytest.raises(password_policy.PasswordPolicyError):
            password_policy.validate("SUP3RSECRET!!")  # upper + digit, no lower

    def test_rejects_missing_uppercase(self) -> None:
        with pytest.raises(password_policy.PasswordPolicyError):
            password_policy.validate("sup3rsecret!!")  # lower + digit, no upper

    def test_rejects_missing_digit(self) -> None:
        with pytest.raises(password_policy.PasswordPolicyError):
            password_policy.validate("SuperSecret!!")  # upper + lower, no digit

    def test_does_not_strip_whitespace(self) -> None:
        # Leading/trailing spaces count toward length and are not removed.
        password_policy.validate(" Sup3rSecretPass! ")  # 17 chars incl. spaces


class TestArgon2idHashingIntegration:
    def test_hashed_password_is_argon2id_and_verifiable(self) -> None:
        hasher = get_password_hasher()
        password = "Sup3rSecretPass!"
        password_policy.validate(password)
        hashed = hasher.hash(password)
        assert hashed.startswith("$argon2id$")
        assert password not in hashed
        assert hasher.verify(password, hashed) is True
        assert hasher.verify("wrong-password", hashed) is False

    def test_same_password_yields_different_hashes(self) -> None:
        hasher = get_password_hasher()
        assert hasher.hash("Sup3rSecretPass!") != hasher.hash("Sup3rSecretPass!")
