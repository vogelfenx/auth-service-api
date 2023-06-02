from .protocol import Storage

storage: Storage | None = None


async def get_db() -> Storage | None:
    """For dependency."""
    return storage
