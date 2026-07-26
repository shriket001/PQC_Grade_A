"""Import all ORM model modules so `Base.metadata` and the mapper registry are
fully populated at app startup (Constitution Principle V).

Each user story adds its models here as they're implemented — mirroring
`alembic/env.py`'s import list. The composition root (`main.py`) imports this
package so every string-referenced relationship resolves the first time a query
touches the mapper.
"""

from . import (  # noqa: F401
    conversation,
    conversation_key_backup,
    email_verification_token,
    identity_key,
    message,
    role,
    session,
    user,
)

__all__ = [
    "conversation",
    "conversation_key_backup",
    "email_verification_token",
    "identity_key",
    "message",
    "role",
    "session",
    "user",
]
