"""Verification-email delivery (Phase 4 / US1).

A Protocol so AuthService stays decoupled from the arq transport. The default
`ArqVerificationEmailSender` enqueues a job consumed by the arq worker
(`workers/email_jobs.send_verification_email`); tests inject a capturing fake
via FastAPI dependency overrides so they can retrieve the emitted token without
a live worker or SMTP server.
"""

from typing import Protocol

from arq.connections import RedisSettings

from src.core.config import get_settings


class VerificationEmailSender(Protocol):
    async def send(self, to_email: str, token: str) -> None: ...


class ArqVerificationEmailSender:
    """Enqueues `send_verification_email` onto the arq queue backed by Redis."""

    def __init__(self, redis_settings: RedisSettings) -> None:
        self._redis_settings = redis_settings

    async def send(self, to_email: str, token: str) -> None:
        # A fresh pool per send is acceptable for Phase 4 volume; the worker
        # (not this enqueue path) is where sustained throughput matters.
        from arq import create_pool

        pool = await create_pool(self._redis_settings)
        try:
            await pool.enqueue_job("send_verification_email", email=to_email, token=token)
        finally:
            await pool.aclose()


def get_redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)
