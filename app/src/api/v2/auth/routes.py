from datetime import timedelta
from typing import Annotated

from core.config import security_settings
from core.logger import get_logger
from db.storage.dependency import get_storage
from db.storage.protocol import UserStorage
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Request,
    Response,
    status,
)
from security.models import Token, TokenData
from security.token import create_token
from starlette.requests import Request

from .oauth2 import Provider, oauth
from .utils import assign

logger = get_logger(__name__)
logger.setLevel(level="DEBUG")
router = APIRouter()


@router.get(
    "/{provider}/login", summary="Redirect a client to authorization page."
)
async def login_via_google(
    provider: Annotated[Provider, Path(description="A social provider.")],
    request: Request,
):
    redirect_uri = str(
        request.url_for(
            "auth_via_provider",
            provider=provider.value,
        )
    )
    current_provider = getattr(oauth, provider.value)

    if not current_provider:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The oauth.{0} must be specified.".format(provider.value),
        )

    return await current_provider.authorize_redirect(request, redirect_uri)


@router.get(
    "/{provider}/authorize",
    summary="Take a code from authorization page and assign to user.",
)
async def auth_via_provider(
    provider: Annotated[Provider, Path(description="A social provider.")],
    request: Request,
    response: Response,
    storage: UserStorage = Depends(get_storage),
):
    current_provider = getattr(oauth, provider.value)

    if not current_provider:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The oauth.{0} must be specified.".format(provider.value),
        )
    token = await current_provider.authorize_access_token(request)
    user = token["userinfo"]

    storage_user = assign(
        token=token,
        user=user,
        storage=storage,
    )

    _roles = storage.get_user_roles(storage_user.username)
    roles = [role.role for role in _roles if not role.disabled]  # type: ignore
    access_token_expires = timedelta(
        minutes=security_settings.access_token_expire_minutes,
    )
    refresh_token_expires = timedelta(
        minutes=security_settings.refresh_token_expire_minutes,
    )

    access_token = create_token(
        data=TokenData(
            username=storage_user.username,
            roles=roles,
        ),
        expires_delta=access_token_expires,
    )
    refresh_token = create_token(
        data=TokenData(
            username=storage_user.username,
            roles=roles,
        ),
        expires_delta=refresh_token_expires,
    )
    response.set_cookie(
        key="access_token",
        value="Bearer {0}".format(access_token),
        httponly=True,
    )
    response.set_cookie(
        key="refresh_token",
        value="Bearer {0}".format(refresh_token),
        httponly=True,
    )

    storage.log_user_event(
        username=storage_user.username,
        event_desc="Token issuance",
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )
