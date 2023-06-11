from datetime import timedelta
from typing import Annotated
from fastapi.security.utils import get_authorization_scheme_param
from api.v1.deps import CurrentUserAnnotated


from core.config import security_settings
from core.logger import get_logger
from db.storage.dependency import get_storage
from db.storage.protocol import Storage, StorageUserModel
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Header,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from security.models import Token
from security.token import (
    create_token,
    decode_token,
    get_current_username_from_token,
    oauth2_scheme,
)
from security.hasher import Hasher
from .service import invalidate_token, is_token_invalidated
from .models import ResponseUser, User, UserAnnotated, Password

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
            detail="Username already exists!",
            headers={"WWW-Authenticate": "Bearer"},
        )

    psw: str = user.password.get_secret_value()
    hashed_password = Hasher.get_password_hash(password=psw)
    storage.set_user(
        **user.dict(exclude={"password"}),
        hashed_password=hashed_password,
    )

    storage.log_user_event(
            username=user.username,
            event_desc="Signup"
            )

    return {"message": "The user has been created!"}


@router.post("/token")
async def login_for_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    storage: Storage = Depends(get_storage),
):
    try:
        user = storage.authenticate_user(
            username=form_data.username,
            password=form_data.password,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=" Username does not exist",
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
        value="Bearer {0}".format(access_token),
        httponly=True,
    )
    response.set_cookie(
        key="refresh_token",
        value="Bearer {0}".format(refresh_token),
        httponly=True,
    )

    storage.log_user_event(
            username=user.username,
            event_desc="Token issuance"
            )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.get("/logout")
async def logout(
    response: Response,
    request: Request,
    current_user: CurrentUserAnnotated,
    storage: Storage = Depends(get_storage),
):
    """Logout the current user.

    Add token to blacklist with expiration date of refresh_token.
    Delete tokens in cookies.
    """
    access_token = request.cookies["access_token"]
    refresh_token = request.cookies["refresh_token"]

    await invalidate_token(
        token=access_token,
        token_name="access_token",
    )
    await invalidate_token(
        token=refresh_token,
        token_name="refresh_token",
    )

    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")

    storage.log_user_event(
            username=current_user,
            event_desc="Logout"
        )

    return status.HTTP_200_OK


@router.get("/user/me")
async def user_me(
    current_user: CurrentUserAnnotated,
    storage: Storage = Depends(get_storage),
) -> ResponseUser:
    """Return current user."""
    user = storage.get_user(username=current_user.username)
    return ResponseUser(
        **user.__dict__,
    )


@router.put("/user/password")
async def change_password(
    response: Response,
    request: Request,
    old_psw: Annotated[str, Query(description='Old user password')],
    new_psw: Annotated[str, Query(description='New user password')],
    current_user: CurrentUserAnnotated,
    storage: Storage = Depends(get_storage),
):
    """Change password for user by id."""

    if not storage.authenticate_user(username=current_user, password=old_psw):
        return status.HTTP_401_UNAUTHORIZED

    access_token = request.cookies["access_token"]
    refresh_token = request.cookies["refresh_token"]

    if await invalidate_token(access_token) and await invalidate_token(
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

    storage.log_user_event(
            username=current_user,
            event_desc="Changing password"
            )

    return {"message": "User password has been updated!"}


@router.put("/user/edit")
async def edit_common_user_info(
    current_user: CurrentUserAnnotated,
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
    current_user: CurrentUserAnnotated,
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
        List of UserHistory class instances
    """

    return storage.get_user_history(
        username=current_user.username,
        history_limit=limit,
    )


@router.post("/refresh")
async def refresh(
    request: Request,
    response: Response,
):
    old_refresh_token = request.cookies.get("refresh_token")
    schema, param = get_authorization_scheme_param(old_refresh_token)

    if not param:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if await is_token_invalidated(param, token_name="refresh_token"):
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

    await invalidate_token(
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
        value="Bearer {0}".format(access_token),
        secure=True,
    )

    response.set_cookie(
        key="refresh_token",
        value="Bearer {0}".format(refresh_token),
        secure=True,
    )
