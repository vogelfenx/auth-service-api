from db.cache.protocol import Cache

cache: Cache | None = None


async def get_cache() -> Cache | None:
    """For dependency."""
    return cache
