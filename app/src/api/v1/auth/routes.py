from datetime import timedelta
from typing import Annotated

from core.config import security_settings
from core.logger import get_logger
from db.storage.dependency import get_storage
from db.storage.protocol import Storage, User
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
)
from security.hasher import Hasher
from .models import UserAnnotated

logger = get_logger(__name__)
logger.setLevel(level="DEBUG")
router = APIRouter()


@router.post("/signin")
async def signin(
    user: UserAnnotated,
    storage: Storage = Depends(get_storage),
):
    """Registration a user."""

    # TODO: Проверить нет ли существующего пользователя и вернуть ошибку, если есть
    if storage.user_exists():
        return status.HTTP_409_CONFLICT

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


@router.get("/logout")
async def logout(token: str = Depends(get_current_username_from_token)):
    """Logout also delete jwt token."""

    # TODO попробовать использовать тут протокол
    if await add_blacklist_token(token):
        # TODO Переделать на orjson
        return status.HTTP_200_OK
    return status.HTTP_500_INTERNAL_SERVER_ERROR


# TODO добавить ручку change_pass (должен производить логаут)
# Igor
@router.put("/user/password")
async def change_password(
    current_user: Annotated[User, Depends(get_current_username_from_token)],
    psw: Annotated[str, Query(description="User hashed password.")],
):
    """Change password for user by id."""

    return {"message": "This is a user editor!"}


@router.put("/user/edit")
async def edit_common_user_info(
    current_user: Annotated[User, Depends(get_current_username_from_token)],
    login: Annotated[str, Query(description="A user login.")],
    psw: Annotated[str, Query(description="User hashed password.")],
):
    """Change login or password for user by id."""

    return {"message": "This is a user editor!"}


@router.get("/user/history")
async def get_user_history(
    current_user: Annotated[User, Depends(get_current_username_from_token)],
):
    """Get user history by id and token."""

    return {"message": "This is a history!"}


@router.post("/refresh")
async def refresh(request: Request, response: Response):
    refresh_token = request.cookies["refresh_token"]

    if not refresh_token:
        raise ValueError("No refresh token")

    payload = decode_token(refresh_token)

    access_token_expires = timedelta(
        minutes=security_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    access_token = create_token(
        data={"sub": payload.get("sub")},
        expires_delta=access_token_expires,
    )

    logger.debug("refresh_token: {0}".format(refresh_token))
    logger.debug("access_token: {0}".format(access_token))

    response.set_cookie(
        key="access_token",
        value=access_token,
        secure=True,
    )
