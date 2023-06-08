from typing import Protocol, Any


class Cache(Protocol):
    """Cache protocol."""

    def hget(self, name: str, key: str) -> str | None:
        """Get value from key within hash name."""
        ...

    def hset(self, name: str, key: str, key_value: Any) -> None:
        """Set key-value pair with hash name."""
        ...

    def delete(self, key: str) -> bool | int | None:
        """Delete key."""
        ...

    def exists(self, key: str) -> bool | int:
        """Return counter of key(s) if key(s) exist(s)."""
        ...

    def expire(self, key: str, seconds: int) -> None:
        """Set expire time in seconds."""
        ...

    def close(self) -> None:
        """Close connection."""
        ...
