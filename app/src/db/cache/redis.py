from datetime import timedelta
from logging import DEBUG
from typing import Any

import orjson
from redis.asyncio import Redis

from core.config import redis_settings
from core.logger import get_logger

logger = get_logger(__name__, DEBUG)


class RedisCache:
    """Async. Redis implementation of Cache protocol."""

    def __init__(
        self,
        host: str = redis_settings.redis_host,
        port: int = redis_settings.redis_port,
    ) -> None:
        logger.debug(
            "Initialize Redis connection on host=%s, port=%s",
            host,
            port,
        )
        self.redis = Redis(
            host=host,
            port=port,
        )

    async def get(self, key: str) -> Any | None:
        """Get value by key."""
        logger.debug("Get value from key '%s'", key)

        key_value = await self.redis.get(name=key)

        if isinstance(key_value, bytes):
            key_value = orjson.loads(key_value.decode("utf-8"))

        return key_value

    async def set(
        self,
        key: str,
        key_value: Any,
        ttl: float | timedelta | None = None,
    ) -> None:
        """Set key-value pair."""
        logger.debug(
            "Set key %s to value %s with expiration %s",
            key,
            key_value,
            ttl,
        )
        await self.redis.set(name=key, value=key_value, ex=ttl)

    async def hget(self, name: str, key: str) -> str | None:
        """Get value from key within hash name."""
        logger.debug(
            "Get value from key %s within hash %s.",
            key,
            name,
        )

        key_value = await self.redis.hget(name=name, key=key)

        if isinstance(key_value, bytes):
            key_value = orjson.loads(key_value.decode("utf-8"))

        return key_value

    async def hset(self, name: str, key: str, key_value: Any) -> None:
        """Set key-value pair with hash name."""
        logger.debug(
            "Set value by key %s within hash %s.",
            key,
            name,
        )

        key_value = await self.redis.hset(
            name=name,
            key=key,
            value=key_value,
        )

    async def delete(self, *keys: list[str]) -> int:
        """Delete key(s).

        Returns the number of keys that were deleted.
        """
        logger.debug(
            "Delete key(s) %s.",
            keys,
        )

        return await self.redis.delete(*keys)

    async def exists(self, *keys: list[str]) -> int:
        """Return counter of key(s) if key(s) exist(s)."""
        logger.debug(
            "Return counter of key(s) %s if key(s) exist(s).",
            keys,
        )
        return await self.redis.exists(*keys)

    async def expire(self, key: str, seconds: int | timedelta) -> None:
        """Set expire time in seconds."""
        logger.debug(
            "Set TTL on key '%s' for %s seconds.",
            key,
            seconds,
        )
        await self.redis.expire(
            name=key,
            time=seconds,
        )

    async def close(self) -> None:
        """Close connection."""
        logger.debug("Close connection.")
        await self.redis.close()
