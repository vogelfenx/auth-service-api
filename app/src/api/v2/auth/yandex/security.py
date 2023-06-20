# """Authentication scheme."""
# from fastapi import Request
# from fastapi.security.oauth2 import OAuth2AuthorizationCodeBearer
# from ..models import Tokens
import base64
from core.config import yandex_auth_settings, api_settings
from loginpass import Yandex

# from authlib.integrations.starlette_client import (
#     OAuthError as OAuthError,
# )

# from starlette.requests import Request

# TOKEN_URL = "v2/auth/yandex/token"
# REFRESH_URL = "v2/auth/yandex/refresh"


# oauth2_scheme = OAuth2AuthorizationCodeBearer(
#     authorizationUrl=yandex_auth_settings.auth_url,
#     tokenUrl=TOKEN_URL,
#     refreshUrl=REFRESH_URL,
# )

from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

# from authlib.common


# def encode_secret():
#     _secret = "{0}:{1}".format(
#         yandex_auth_settings.client_id,
#         yandex_auth_settings.client_secret,
#     )
#     authorization = base64.b64encode(bytes(_secret, "utf-8"))
#     return authorization


from loginpass.yandex import Yandex

oauth = OAuth()
oauth.register(
    name=Yandex.NAME,
    client_id=yandex_auth_settings.yandex_id,
    client_secret=yandex_auth_settings.yandex_secret,
    authorize_params={
        "Content-type": "application/x-www-form-urlencoded",
    },
    client_kwargs={
        "verify": False,
        "trust_env": True,
        "timeout": 0,
    },
    access_token_params={
        "response_type": "code",
        "Content-type": "application/x-www-form-urlencoded",
        "client_id": yandex_auth_settings.yandex_id,
    },
    **Yandex.OAUTH_CONFIG,
)

# oauth.register(
#     name="yandex",
#     client_id=yandex_auth_settings.client_id,
#     client_secret=yandex_auth_settings.client_secret,
#     access_token_url=yandex_auth_settings.auth_url,
#     access_token_params={
#         "response_type": "code",
#     },
#     authorize_url=yandex_auth_settings.auth_url,
#     authorize_params={
#         "Content-type": "application/x-www-form-urlencoded",
#     },
#     api_base_url="https://login.yandex.ru",
#     client_kwargs={
#         "verify": False,
#     },
#     userinfo_endpoint ='info',
#     userinfo_compliance_fix=normalize_userinfo,
# )

# def get_tokens(
#     request: Request,
# ) -> Tokens:
#     return Tokens.parse_obj(request.cookies)
