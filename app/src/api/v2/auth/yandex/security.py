# """Authentication scheme."""
from core.config import yandex_auth_settings
from loginpass import Yandex
from authlib.integrations.starlette_client import OAuth
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
