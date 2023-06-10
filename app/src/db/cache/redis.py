# Реализовать хранение недействительных access_token и refresh_token.
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
        host: str | None = redis_settings.REDIS_HOST,
        port: int | None = redis_settings.REDIS_PORT,
    ) -> None:
        logger.debug(
            f"Initialize Redis connection on host={host}, port={port}",
        )
        self.redis = Redis(
            host=host,
            port=port,
        )

    async def get(self, key: str) -> Any | None:
        """Get value by key."""
        logger.debug(f"Get value from key '{key}'")

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
        # FIXME Кирилл, здесь и в остальных местах поправить форматирование строк
        logger.debug(
            f"Set key '{key}' to value {key_value} with expiration {ttl}'",
        )
        await self.redis.set(name=key, value=key_value, ex=ttl)

    async def hget(self, name: str, key: str) -> str | None:
        """Get value from key within hash name."""
        logger.debug(f"Get value from key '{key}' within hash '{name}'.")

        key_value = await self.redis.hget(name=name, key=key)

        if isinstance(key_value, bytes):
            key_value = orjson.loads(key_value.decode("utf-8"))

        return key_value

    async def hset(self, name: str, key: str, key_value: Any) -> None:
        """Set key-value pair with hash name."""
        logger.debug(f"Set value by key '{key}' within hash '{name}'.")

        key_value = await self.redis.hset(
            name=name,
            key=key,
            value=key_value,
        )

    async def delete(self, *keys: list[str]) -> int:
        """Delete key(s).

        Returns the number of keys that were deleted.
        """
        logger.debug(f"Delete key(s) {keys}.")

        return self.redis.delete(*keys)

    async def exists(self, *keys: list[str]) -> int:
        """Return counter of key(s) if key(s) exist(s)."""
        logger.debug(f"Return counter of key(s) {keys} if key(s) exist(s).")
        return await self.redis.exists(*keys)

    async def expire(self, key: str, seconds: int | timedelta) -> None:
        """Set expire time in seconds."""
        logger.debug(f"Set TTL on key '{key}' for {seconds} seconds.")
        await self.redis.expire(
            name=key,
            time=seconds,
        )

    async def close(self) -> None:
        """Close connection."""
        logger.debug("Close connection.")
        await self.redis.close()
