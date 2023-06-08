from datetime import datetime, timedelta
from typing import Annotated
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from db.storage.dependency import get_storage
from db.storage.protocol import Storage, User
from db.cache.dependency import get_cache
from db.cache.protocol import Cache

from src.db.storage.auth_db import PgConnector

from core.logger import get_logger
from core.config import security_settings

logger = get_logger(__name__)

# Error
CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="v1/auth/token")


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
):
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

    return token_data.username


async def get_current_user_token(
    token: Annotated[str, Depends(oauth2_scheme)]
):
    return token


async def add_blacklist_token(
    token: Annotated[str, Depends(oauth2_scheme)],
    token_name: str,
) -> None:
    """Add a token to blacklist to invalidate it."""
    cache = await get_cache()
    decoded_token = decode_token(token)

    username = decoded_token.get("sub")
    token_ttl = decoded_token.get("exp")

    token_key = f"{username}:{token_name}:{token}"

    await cache.set(
        key=token_key,
        key_value=token,
        ttl=token_ttl,
    )
