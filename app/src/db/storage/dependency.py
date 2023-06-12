from .protocol import Storage

storage: Storage | None = None


async def get_storage() -> Storage:
    """For dependency."""
    if not storage:
        raise ValueError("Storage must be initializated.")
    return storage
