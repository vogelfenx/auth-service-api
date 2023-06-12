import re
from datetime import datetime, timedelta
from typing import Annotated

from core.config import security_settings
from core.logger import get_logger
from fastapi import Depends, HTTPException, status
from fastapi.security.utils import get_authorization_scheme_param
from jose import JWTError, jwt

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
    data: TokenData,
    expires_delta: timedelta | None = None,
):
    to_encode = dict(data)
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        claims=to_encode,
        key=security_settings.secret_key,
        algorithm=security_settings.algorithm,
    )
    return encoded_jwt


def decode_token(token: str):
    if re.search(string=token.lower(), pattern="^bearer "):
        _, token = get_authorization_scheme_param(token)

    payload = jwt.decode(
        token=token,
        key=security_settings.secret_key,
        algorithms=[security_settings.algorithm],
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
        username: str | None = payload.get("username")
        if username is None:
            raise credentials_exception
        token_data = TokenData.parse_obj(payload)
    except JWTError:
        raise credentials_exception

    return token_data


async def get_current_user_token(
    token: Annotated[str, Depends(oauth2_scheme)]
):
    return token
