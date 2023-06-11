from db.cache.dependency import get_cache
from security.token import decode_token

async def invalidate_token(
    token: str,
    token_name: str,
) -> None:
    """Add a token to blacklist to invalidate it."""
    cache = await get_cache()
    decoded_token = decode_token(token)

    username = decoded_token.get("sub")
    token_ttl = decoded_token.get("exp")

    # FIXME Кирилл, дублируется токен в кэше, нужно использовать другой подход.
    # Например, хранить массив в {username}:{token_name} (redis уменнт это делать нативно).
    token_key = f"{username}:{token_name}:{token}"

    await cache.set(
        key=token_key,
        key_value=token,
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

    # FIXME Кирилл, дублируется токен в кэше, нужно использовать другой подход.
    # Например, хранить массив в {username}:{token_name} (redis уменнт это делать нативно).
    token_key = f"{username}:{token_name}:{token}"

    return await cache.exists(token_key) > 0
