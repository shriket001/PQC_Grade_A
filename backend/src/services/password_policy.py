"""Password complexity policy (FR-001).

The documented policy, enforced identically at registration and password-reset
time: a minimum of 12 characters containing at least one lowercase letter, one
uppercase letter, and one digit. A special character is deliberately NOT
required (usability) — length plus three character classes gives strong
resistance to online guessing, which FR-014's rate limiting further blunts.

This is the single source of truth for the policy; both the registration and the
(Phase 9) password-reset flows call `validate`.
"""

MIN_LENGTH = 12


class PasswordPolicyError(ValueError):
    """Raised when a password does not meet the documented complexity policy."""


def _missing_classes(password: str) -> list[str]:
    missing: list[str] = []
    if not any(c.islower() for c in password):
        missing.append("one lowercase letter")
    if not any(c.isupper() for c in password):
        missing.append("one uppercase letter")
    if not any(c.isdigit() for c in password):
        missing.append("one digit")
    return missing


def validate(password: str) -> None:
    """Raise PasswordPolicyError if `password` fails the documented policy."""
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"password must be at least {MIN_LENGTH} characters")
    missing = _missing_classes(password)
    if missing:
        raise PasswordPolicyError("password must contain " + ", ".join(missing))
