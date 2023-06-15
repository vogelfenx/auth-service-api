"""Authentication scheme."""
from typing import Annotated, Any
from fastapi import Depends, HTTPException, Request, status
from fastapi.security.oauth2 import OAuth2AuthorizationCodeBearer, OAuth2
from api.v1.auth.models import Tokens
from core.config import yandex_auth_settings
from security.models import TokenData
from authlib.integrations.starlette_client import (
    OAuth,
    OAuthError as OAuthError,
)
from starlette.config import Config

# from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request

TOKEN_URL = "v1/auth/yandex/token"
REFRESH_URL = "v1/auth/yandex/refresh"


oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=yandex_auth_settings.auth_url,
    tokenUrl=TOKEN_URL,
    refreshUrl=REFRESH_URL,
)


def get_tokens(
    request: Request,
) -> Tokens:
    return Tokens.parse_obj(request.cookies)
