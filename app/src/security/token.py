import re
from datetime import datetime, timedelta
from typing import Annotated

from core.config import security_settings
from core.logger import get_logger
from fastapi import Depends, HTTPException, status
from fastapi.security.utils import get_authorization_scheme_param
from jose import JWTError, jwt

from .models import TokenData

logger = get_logger(__name__)

# Error
CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


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


# TODO убрать default values
def decode_token(
    token: str,
    key: str = security_settings.secret_key,
    algorithms: list[str] = [security_settings.algorithm],
):
    if re.search(string=token.lower(), pattern="^bearer "):
        _, token = get_authorization_scheme_param(token)

    payload = jwt.decode(
        token=token,
        key=key,
        algorithms=algorithms,
    )

    exp = payload.get("exp")
    if not exp:
        raise ValueError("Wrong payload")

    # Check if token is not expired
    if datetime.utcfromtimestamp(exp) < datetime.utcnow():
        raise ValueError("Refresh token expired")

    return payload
