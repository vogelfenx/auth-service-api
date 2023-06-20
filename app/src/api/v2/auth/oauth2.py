# """Authentication scheme."""
from core.config import (
    google_auth_settings,
    vk_auth_settings,
    yandex_auth_settings,
)

from authlib.integrations.starlette_client import OAuth
from loginpass import Google as Google, VK, Yandex
from enum import Enum


class Provider(str, Enum):
    google = "google"
    vk = "vk"


oauth = OAuth()

oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile",
        "verify": False,
    },
    client_id=google_auth_settings.google_id,
    client_secret=google_auth_settings.google_secret,
)

oauth.register(
    name="vk",
    client_id=vk_auth_settings.vk_id,
    client_secret=vk_auth_settings.vk_secret,
    **VK.OAUTH_CONFIG,
)

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
        "timeout": 120,
    },
    access_token_params={
        "response_type": "code",
        "Content-type": "application/x-www-form-urlencoded",
        "client_id": yandex_auth_settings.yandex_id,
    },
    **Yandex.OAUTH_CONFIG,
)
