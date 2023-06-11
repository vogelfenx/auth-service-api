from db.cache.dependency import get_cache
from security.token import decode_token
from db.cache.protocol import Cache
from core.logger import get_logger

logger = get_logger(__name__, logging_level="DEBUG")


def _fromat_token_key_for_cache(
    username: str,
    token_name: str,
    token: str,
) -> str:
    return f"{username}:{token_name}:{token}"


async def invalidate_token(
    token: str,
    token_name: str,
) -> None:
    """Add a token to blacklist to invalidate it."""
    cache = await get_cache()
    decoded_token = decode_token(token)

    username = decoded_token.get("sub")
    token_ttl = decoded_token.get("exp")

    token_key = _fromat_token_key_for_cache(
        username=username,
        token_name=token_name,
        token=token,
    )

    # key_value doesn't matter because token is stored in key
    # to make key unique when user logs in from multiple devices
    await cache.set(
        key=token_key,
        key_value=1,
        ttl=token_ttl,
    )


async def is_token_invalidated(
    token: str,
    token_name: str,
) -> bool:
    """Check if token is in blacklist."""

    cache = await get_cache()

    decoded_token = decode_token(token)
    username = decoded_token.get("sub")

    token_key = _fromat_token_key_for_cache(
        username=username,
        token_name=token_name,
        token=token,
    )

    return await cache.exists(token_key) > 0
