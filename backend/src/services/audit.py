"""Audit-logging hook (T047 — stubbed against the interface US11 finalizes).

Mirrors the `ErrorSink` pattern in core/error_handling.py: AuthService depends
on the `AuditLogger` Protocol and calls it for every security-relevant auth
event (register, email_verified, login success/failure, logout). The default
`NoOpAuditLogger` does nothing; US11 swaps in a DB-backed implementation that
persists `AuditLogEntry` records — this Protocol and the call sites do not
change, only the injected implementation does.
"""

from typing import Protocol
from uuid import UUID


class AuditLogger(Protocol):
    async def record(
        self, *, action: str, actor_id: UUID | None, outcome: str, context: dict[str, object]
    ) -> None: ...


class NoOpAuditLogger:
    """Default stub. US11 replaces this with a DB-backed AuditService."""

    async def record(
        self, *, action: str, actor_id: UUID | None, outcome: str, context: dict[str, object]
    ) -> None:
        return None
