"""arq background-worker scaffold.

Story-specific jobs (email_jobs.py, etc.) register their functions in the
`functions` list below as they're implemented (US1 and US7).
"""

from collections.abc import Callable, Coroutine
from typing import Any

from arq.connections import RedisSettings

from src.core.config import get_settings
from src.workers.email_jobs import send_verification_email


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


class WorkerSettings:
    functions: list[Callable[..., Coroutine[Any, Any, Any]]] = [send_verification_email]
    redis_settings = _redis_settings()
