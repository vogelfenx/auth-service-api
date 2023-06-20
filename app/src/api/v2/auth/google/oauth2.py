# """Authentication scheme."""
from core.config import google_auth_settings, vk_auth_settings

from authlib.integrations.starlette_client import OAuth
from loginpass import Google, VK
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
