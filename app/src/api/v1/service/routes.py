from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query

router = APIRouter()


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
