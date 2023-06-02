from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

router = APIRouter()


@router.post(
    "/role",
    status_code=status.HTTP_200_OK,
)
async def create_role():
    """Create a role by id."""

    return {"message": "This is create role entrypoint!"}


@router.delete("/role/{role_id}")
async def delete_role():
    """Delete a role by id."""

    return {"message": "This is delete role entrypoint!"}


@router.put("/role/{role_id}")
async def edit_role():
    """Change a role by id."""

    return {"message": "This is edit role entrypoint!"}


@router.get("/roles")
async def return_roles():
    """Fetch all roles."""

    return {"message": "This is create role entrypoint!"}


@router.post(
    "/assign",
    status_code=status.HTTP_200_OK,
)
async def assign(
    role_id: Annotated[str, Query(description="A role id.")],
    user_id: Annotated[str, Query(description="A user id.")],
):
    """Assign a role to a user."""

    return {"message": "This is create role entrypoint!"}


@router.post(
    "/validate/{user_id}",
    status_code=status.HTTP_200_OK,
)
async def validate():
    """Validate that a user has permissions."""
    pass
