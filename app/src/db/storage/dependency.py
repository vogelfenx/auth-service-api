from .protocol import Storage

storage: Storage | None = None


async def get_storage() -> Storage | None:
    """For dependency."""
    return storage
