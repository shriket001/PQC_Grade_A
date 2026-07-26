"""Async Redis client — backs session revocation, presence, rate limiting, and pub/sub."""

from functools import lru_cache

from redis.asyncio import Redis

from src.core.config import get_settings


@lru_cache
def get_redis() -> Redis:
    return Redis.from_url(get_settings().redis_url, decode_responses=True)  # type: ignore[no-any-return]
