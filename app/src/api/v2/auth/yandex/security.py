"""Authentication scheme."""
from fastapi import Request
from fastapi.security.oauth2 import OAuth2AuthorizationCodeBearer
from ..models import Tokens
from core.config import yandex_auth_settings
from authlib.integrations.starlette_client import (
    OAuthError as OAuthError,
)

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
