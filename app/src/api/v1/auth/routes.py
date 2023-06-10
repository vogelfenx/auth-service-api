from datetime import timedelta
from os import access
from typing import Annotated
from urllib import response

from core.config import security_settings
from core.logger import get_logger
from db.storage.dependency import get_storage
from db.storage.protocol import Storage, StorageUserModel
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from security.token import (
    Token,
    add_blacklist_token,
    create_token,
    decode_token,
    get_current_username_from_token,
    oauth2_scheme,
)
from security.hasher import Hasher
from security.token import is_token_invalidated
from .models import UserAnnotated

logger = get_logger(__name__)
logger.setLevel(level="DEBUG")
router = APIRouter()


@router.post("/signup")
async def signup(
    user: UserAnnotated,
    storage: Storage = Depends(get_storage),
):
    """Registration a user."""

    if storage.user_exists(user.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    psw: str = user.password.get_secret_value()
    hashed_password = Hasher.get_password_hash(password=psw)
    storage.set_user(
        **user.dict(exclude={"password"}),
        hashed_password=hashed_password,
    )

    return {"message": "The user has been created!"}


@router.post("/token")
async def login_for_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    storage: Storage = Depends(get_storage),
):
    user = storage.authenticate_user(
        username=form_data.username,
        password=form_data.password,
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(
        minutes=security_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    refresh_token_expires = timedelta(
        minutes=security_settings.REFRESH_TOKEN_EXPIRE_MINUTES,
    )

    access_token = create_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )
    refresh_token = create_token(
        data={"sub": user.username},
        expires_delta=refresh_token_expires,
    )
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/logout")
async def logout(
    response: Response,
    request: Request,
):
    """Logout the current user.

    Add token to blacklist with expiration date of refresh_token.
    Delete tokens in cookies.
    """
    access_token = request.cookies["access_token"]
    refresh_token = request.cookies["refresh_token"]

    await add_blacklist_token(
        token=access_token,
        token_name="access_token",
    )
    await add_blacklist_token(
        token=refresh_token,
        token_name="refresh_token",
    )

    # TODO: хотим ли мы удалять ключи на стороне клиента?
    # response.delete_cookie(key="access_token")
    # response.delete_cookie(key="refresh_token")

    return status.HTTP_200_OK


@router.put("/user/password")
async def change_password(
    response: Response,
    request: Request,
    current_user: Annotated[
        StorageUserModel, Depends(get_current_username_from_token)
    ],
    new_psw: Annotated[str, Query(description="New user password.")],
    old_psw: Annotated[str, Query(description="Old user password.")],
    storage: Storage = Depends(get_storage),
):
    """Change password for user by id."""

    if not storage.authenticate_user(username=current_user, password=old_psw):
        return status.HTTP_401_UNAUTHORIZED

    access_token = request.cookies["access_token"]
    refresh_token = request.cookies["refresh_token"]

    if await add_blacklist_token(access_token) and await add_blacklist_token(
        refresh_token
    ):
        storage.update_user_password(username=current_user, password=new_psw)

    access_token_expires = timedelta(
        minutes=security_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    refresh_token_expires = timedelta(
        minutes=security_settings.REFRESH_TOKEN_EXPIRE_MINUTES,
    )

    access_token = create_token(
        data={"sub": current_user},
        expires_delta=access_token_expires,
    )
    refresh_token = create_token(
        data={"sub": current_user},
        expires_delta=refresh_token_expires,
    )
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
    )

    return {"message": "User password has been updated!"}


@router.put("/user/edit")
async def edit_common_user_info(
    current_user: Annotated[
        StorageUserModel, Depends(get_current_username_from_token)
    ],
    psw: Annotated[str, Query(description="User password.")],
    email: Annotated[str | None, Query(description="User email.")],
    full_name: Annotated[str | None, Query(description="User full name.")],
    disabled: Annotated[bool, Query(description="Disabled user flag.")],
    storage: Storage = Depends(get_storage),
):
    """Change login or password for user by username."""
    if not storage.authenticate_user(username=current_user, password=psw):
        return status.HTTP_400_BAD_REQUEST

    user_info = {"email": email, "full_name": full_name, "disabled": disabled}

    storage.edit_user(username=current_user.username, **user_info)

    return {"message": "User has been changed!"}


@router.get("/user/history")
async def get_user_history(
    current_user: Annotated[
        StorageUserModel, Depends(get_current_username_from_token)
    ],
    limit: Annotated[int | None, Query(description="User history limit")],
    storage: Storage = Depends(get_storage),
):
    """
    Get user login history

    Args:
        current_user: user name of specified user
        limit: User history limit
        storage: Storage class

    Returns:
        List of LoginHistory class instances
    """
    return storage.get_user_history(username=current_user, history_limit=limit)


@router.post("/refresh")
async def refresh(request: Request, response: Response):
    old_refresh_token = request.cookies.get("refresh_token")

    if not old_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if await is_token_invalidated(
        old_refresh_token, token_name="refresh_token"
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalidated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(old_refresh_token)

    access_token_expires = timedelta(
        minutes=security_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )

    refresh_token_expires = timedelta(
        minutes=security_settings.REFRESH_TOKEN_EXPIRE_MINUTES,
    )

    access_token = create_token(
        data={"sub": payload.get("sub")},
        expires_delta=access_token_expires,
    )

    await add_blacklist_token(
        token=old_refresh_token,
        token_name="refresh_token",
    )

    refresh_token = create_token(
        data={"sub": payload.get("sub")},
        expires_delta=refresh_token_expires,
    )

    logger.debug("New refresh_token: {0}".format(refresh_token))
    logger.debug("New access_token: {0}".format(access_token))

    response.set_cookie(
        key="access_token",
        value=access_token,
        secure=True,
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        secure=True,
    )
