from fastapi import HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from fastapi import status
from .models import Token

# def _get_authorization_scheme_param(token) -> Token:
#     scheme, param = get_authorization_scheme_param(token)
#         if not token or scheme.lower() != "bearer":
#             if self.auto_error:
#                 raise HTTPException(
#                     status_code=status.HTTP_401_UNAUTHORIZED,
#                     detail="Not authenticated",
#                     headers={"WWW-Authenticate": "Bearer"},
#                 )
#             else:
#                 return None
#     return param


class OAuth2PasswordCookiesBearer(OAuth2PasswordBearer):
    async def __call__(self, request: Request) -> str | None:
        authorization = request.cookies.get("access_token")

        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param
