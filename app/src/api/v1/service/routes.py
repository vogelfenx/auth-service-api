from datetime import timedelta
from http import HTTPStatus
from typing import Annotated
from uuid import UUID
from fastapi.security import OAuth2PasswordRequestForm

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from security.token.jwt import (
    Token,
    User,
    authenticate_user,
    create_access_token,
    fake_users_db,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    get_current_active_user,
)

router = APIRouter()


# Igor
@router.post("/signin")
async def signin(
    user_id: Annotated[str, Query(description="A user id.")],
    psw: Annotated[str, Query(description="User`s password.")],
):
    """Registration a user."""

    return {"message": "This is signin!"}


@router.get("/login")
async def login(
    user_id: Annotated[str, Query(description="A user login.")],
    psw: Annotated[str, Query(description="User`s password.")],
):
    """Return two jwt tokens, if user is registred."""

    return {"message": "This is login!"}


@router.put("/update")
async def update_token():
    """Return two jwt tokens, if user is registred."""

    return {"message": "This is update_token!"}


@router.get("/logout")
async def logout():
    """Logout also delete jwt token."""

    return {"message": "This is logout!"}


# Igor
@router.put("/user")
async def edit_user(
    login: Annotated[str, Query(description="A user login.")],
    psw: Annotated[str, Query(description="User`s hashed password.")],
):
    """Change login or password for user by id."""

    return {"message": "This is a user editor!"}


@router.get("/user/history")
async def get_user_history():
    """Get user`s history by id and token."""

    return {"message": "This is a history!"}


##### Test jwt example
@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(
        fake_users_db, form_data.username, form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


@router.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"item_id": "Foo", "owner": current_user.username}]
