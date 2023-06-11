from .protocol import UserStorage

storage: UserStorage | None = None


async def get_storage() -> UserStorage | None:
    """For dependency."""
    return storage
