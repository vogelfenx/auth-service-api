import re
from datetime import datetime, timedelta
from typing import Annotated

from core.config import security_settings
from core.logger import get_logger
from db.cache.dependency import get_cache
from fastapi import Depends, HTTPException, status
from fastapi.security.utils import get_authorization_scheme_param
from jose import JWTError, jwt

# from fastapi.security import OAuth2PasswordBearer
from .bearers import OAuth2PasswordCookiesBearer
from .models import TokenData

logger = get_logger(__name__)

# Error
CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


oauth2_scheme = OAuth2PasswordCookiesBearer(tokenUrl="v1/auth/token")


def create_token(
    data: dict,
    expires_delta: timedelta | None = None,
):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        claims=to_encode,
        key=security_settings.SECRET_KEY,
        algorithm=security_settings.ALGORITHM,
    )
    return encoded_jwt


def decode_token(token: str):
    if re.search(string=token.lower(), pattern="^bearer "):
        _, token = get_authorization_scheme_param(token)

    payload = jwt.decode(
        token=token,
        key=security_settings.SECRET_KEY,
        algorithms=[security_settings.ALGORITHM],
    )

    exp = payload.get("exp")
    if not exp:
        raise ValueError("Wrong payload")

    # Check if token is not expired
    if datetime.utcfromtimestamp(exp) < datetime.utcnow():
        raise ValueError("Refresh token expired")

    return payload


async def get_current_username_from_token(
    token: Annotated[str, Depends(oauth2_scheme)]
) -> TokenData:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    return token_data


async def get_current_user_token(
    token: Annotated[str, Depends(oauth2_scheme)]
):
    return token


# FIXME Кирилл, ручку следует перенести в другое место,
# токен ничего не должен знать о кэше
async def add_blacklist_token(
    token: Annotated[str, Depends(oauth2_scheme)],
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


# FIXME Кирилл, ручку следует перенести в другое место,
# токен ничего не должен знать о кэше
async def is_token_invalidated(
    token: Annotated[str, Depends(oauth2_scheme)],
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
