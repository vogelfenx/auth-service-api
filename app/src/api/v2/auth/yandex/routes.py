import base64
import ssl
from typing import Annotated
from urllib.parse import urlencode
from uuid import uuid4

import aiohttp
import certifi
from core.config import yandex_auth_settings
from core.logger import get_logger
from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Response,
    status,
)
from pydantic import BaseModel

from ..models import Tokens, Url
from .models import UserInfo
from .security import get_tokens, oauth2_scheme

logger = get_logger(__name__)
logger.setLevel(level="DEBUG")
router = APIRouter()


@router.get(
    "/example", summary="Step 1: Client recieves a login url and redirects."
)
async def example(example=Depends(oauth2_scheme)):
    pass


@router.post(
    "/example_token",
    summary="Step 2: Exchange a code to tokens.",
)
async def example_token(
    response: Response,
    body=Body(),
):
    pass


@router.get(
    "/login", summary="Step 1: Client recieves a login url and redirects."
)
async def get_login_url(
    redirect_uri: Annotated[
        str, Query(description="Callback uri.")
    ] = yandex_auth_settings.callback_url,
) -> Url:
    """
    Get login url which will redirect user to Yandex Authorization Page.
    Use it on a client side.
    """

    params = {
        "response_type": "code",
        "client_id": yandex_auth_settings.client_id,
        "redirect_uri": redirect_uri,
        "state": str(uuid4()),
    }

    return Url(
        url="{0}?{1}".format(
            yandex_auth_settings.auth_url,
            urlencode(params),
        )
    )


@router.post(
    "/token",
    summary="Step 2: Exchange a code to tokens.",
)
async def token(
    response: Response,
    code: Annotated[str, Query(regex=r"\d*", description="Approval code")],
    grant_type: Annotated[
        str, Query(description="Grant type privilegies")
    ] = "authorization_code",
    client_id: Annotated[
        str, Query(description="Client identity")
    ] = yandex_auth_settings.client_id,
    client_secret: Annotated[
        str, Query(description="Client secret")
    ] = yandex_auth_settings.client_secret,
    device_id: Annotated[
        str | None, Query(description="Device identity")
    ] = None,
    device_name: Annotated[
        str | None, Query(description="Device Name")
    ] = None,
):
    """Endoint accepts code and return accept and refresh tokens."""
    data = {
        "code": code,
        "grant_type": grant_type,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if device_id:
        data["device_id"] = device_id
    if device_name:
        data["device_name"] = device_name

    ssl_context = ssl.create_default_context(cafile=certifi.where())

    # FIXME использовать сертификат
    async with aiohttp.ClientSession() as session:
        async with session.post(
            yandex_auth_settings.token_url,
            data=data,
            ssl=False,
        ) as yandex_response:
            tokens_json = await yandex_response.json()
            if yandex_response.status != status.HTTP_200_OK:
                raise HTTPException(
                    status_code=yandex_response.status,
                    detail=tokens_json,
                )

            tokens = Tokens.parse_obj(tokens_json)

    response.set_cookie(
        key="access_token",
        value="Bearer {0}".format(tokens.access_token),
        httponly=True,
    )
    response.set_cookie(
        key="refresh_token",
        value="Bearer {0}".format(tokens.refresh_token),
        httponly=True,
    )

    # TODO рассмотреть возможность логирование входов-выходов с учеткой Yandex
    # user_storage.log_user_event(
    #     username=user.username, event_desc="Token issuance"
    # )
    logger.info("Success authorization!")

    return tokens


@router.get(
    "/user/info",
    response_model=UserInfo,
    summary="Get current user information from Yandex.",
)
async def get_user_info(
    url: Annotated[
        str, Query(description="User info url")
    ] = yandex_auth_settings.user_url,
    tokens: Tokens = Depends(get_tokens),
):
    # access_token = decode_token(
    #     token=tokens.access_token,
    #     key=yandex_auth_settings.client_secret,
    #     algorithms=[security_settings.algorithm],
    # )
    token = tokens.access_token.split()[1]
    async with aiohttp.ClientSession() as session:
        async with session.post(
            url,
            headers={
                "Authorization": "OAuth {0}".format(token),
            },
            ssl=False,
        ) as yandex_response:
            _json = await yandex_response.json()
            if yandex_response.status != status.HTTP_200_OK:
                raise HTTPException(
                    status_code=yandex_response.status,
                    detail=_json,
                )

            user_info = UserInfo.parse_obj(_json)

    return user_info


@router.get(
    "/revoke_token",
    summary="Revoke current access token.",
)
async def revoke_token(
    url: Annotated[
        str, Query(description="Revoke token url")
    ] = yandex_auth_settings.revoke_token_url,
    tokens: Tokens = Depends(get_tokens),
):
    token = tokens.access_token.split()[1]
    _secret = "{0}:{1}".format(
        yandex_auth_settings.client_id,
        yandex_auth_settings.client_secret,
    )
    authorization = base64.b64encode(bytes(_secret, "utf-8"))

    async with aiohttp.ClientSession() as session:
        async with session.post(
            url,
            data={
                "access_token": token,
            },
            headers={
                "Content-type": "application/x-www-form-urlencoded",
                "Authorization": "Basic {0}".format(
                    str(authorization, "utf-8")
                ),
            },
            ssl=False,
        ) as yandex_response:
            _json = await yandex_response.json()
            if (
                yandex_response.status == status.HTTP_400_BAD_REQUEST
                and _json["error"] == "unsupported_token_type"
            ):
                # TODO clear token from local storage
                pass
            elif yandex_response.status != status.HTTP_200_OK:
                raise HTTPException(
                    status_code=yandex_response.status,
                    detail=_json,
                )

    return _json
