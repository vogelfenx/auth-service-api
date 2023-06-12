from db.cache.protocol import Cache

cache: Cache | None = None


async def get_cache() -> Cache:
    """For dependency."""
    if not cache:
        raise ValueError("Cache must be initializated.")
    return cache
