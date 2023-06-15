from typing import Annotated

from fastapi import Depends, HTTPException, status
from jose import JWTError
from security.bearers import OAuth2PasswordCookiesBearer
from security.models import TokenData
from security.token import decode_token


oauth2_scheme = OAuth2PasswordCookiesBearer(tokenUrl="v1/auth/token")


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
