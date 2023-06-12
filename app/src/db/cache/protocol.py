from datetime import timedelta
from typing import Protocol, Any


class Cache(Protocol):
    """Cache protocol."""

    async def get(
        self,
        key: str,
    ) -> Any | None:
        """Get value by key."""
        ...

    async def set(
        self,
        key: str,
        key_value: Any,
        ttl: float | timedelta | None,
    ) -> None:
        """Set key-value pair."""
        ...

    async def hget(
        self,
        name: str,
        key: str,
    ) -> Any | None:
        """Get value from key within hash name."""
        ...

    async def hset(
        self,
        name: str,
        key: str,
        key_value: Any,
    ) -> None:
        """Set key-value pair with hash name."""
        ...

    async def delete(
        self,
        key: str,
    ) -> bool | int | None:
        """Delete key."""
        ...

    async def exists(
        self,
        *keys,
    ) -> bool | int:
        """Return counter of key(s) if key(s) exist(s)."""
        ...

    async def expire(
        self,
        key: str,
        seconds: int,
    ) -> None:
        """Set expire time in seconds."""
        ...

    async def close(self) -> None:
        """Close connection."""
        ...
