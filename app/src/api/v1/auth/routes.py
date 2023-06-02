from datetime import timedelta
from http import HTTPStatus
from typing import Annotated
from uuid import UUID

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
from security.token.jwt import (
    CREDENTIALS_EXCEPTION,
    Token,
    User,
    add_blacklist_token,
    authenticate_user,
    create_token,
    decode_token,
    get_current_active_user,
    get_current_user_token,
)
from core.logger import get_logger
from core.config import security_settings


logger = get_logger(__name__)
logger.setLevel(level="DEBUG")
router = APIRouter()


# Igor
@router.post("/signin")
async def signin(
    user_id: Annotated[str, Query(description="A user id.")],
    psw: Annotated[str, Query(description="User password.")],
):
    """Registration a user."""

    return {"message": "This is signin!"}


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(
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
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.put("/update", response_model=Token)
async def update_token(
    current_user: Annotated[User, Depends(get_current_active_user)],
    current_token: Annotated[User, Depends(get_current_user_token)],
):
    """Return two jwt tokens, if user is registred."""

    access_token_expires = timedelta(
        minutes=security_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    access_token = create_token(
        data={"sub": current_user.username},
        expires_delta=access_token_expires,
    )

    # TODO: старый токен следует записать в cache

    logger.debug("old_token: {0}".format(current_token))
    logger.debug("new_token: {0}".format(access_token))

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/logout")
async def logout(token: str = Depends(get_current_user_token)):
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
    current_user: Annotated[User, Depends(get_current_active_user)],
    psw: Annotated[str, Query(description="User hashed password.")],
):
    """Change password for user by id."""

    return {"message": "This is a user editor!"}


@router.put("/user/edit")
async def edit_common_user_info(
    current_user: Annotated[User, Depends(get_current_active_user)],
    login: Annotated[str, Query(description="A user login.")],
    psw: Annotated[str, Query(description="User hashed password.")],
):
    """Change login or password for user by id."""

    return {"message": "This is a user editor!"}


@router.get("/user/history")
async def get_user_history(
    current_user: Annotated[User, Depends(get_current_active_user)],
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
