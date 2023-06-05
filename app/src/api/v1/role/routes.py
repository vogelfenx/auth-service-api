from logging import DEBUG, INFO
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from core.logger import get_logger

from .models import Role
from .service import RoleService, get_role_service

logger = get_logger(__name__, DEBUG)

router = APIRouter()


@router.post(
    "/",
    status_code=status.HTTP_200_OK,
)
async def create_role(
    role: Role,
    role_service: RoleService = Depends(get_role_service),
) -> dict[str, UUID]:
    """Create a new role."""

    try:
        created_role = role_service.create_role(role=role)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return {'uuid': created_role.id}


@router.delete("/role/{role_id}")
async def delete_role(
    role_id: Annotated[UUID, Path(description="ID of the role to delete")],
    role_service: RoleService = Depends(get_role_service),
) -> None:
    """Delete a role by id."""

    try:
        role_service.delete_role_by_id(role_id=role_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@router.put("/role/{role_id}")
async def edit_role(
    role_id: Annotated[UUID, Path(description="ID of the role to edit")],
    role: Role,
    role_service: RoleService = Depends(get_role_service),
):
    """Edit a role by id."""
    try:
        role_service.edit_role_by_id(role_id=role_id, role=role)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@router.get("/roles", response_model=list[Role])
async def fetch_roles(role_service: RoleService = Depends(get_role_service)):
    """Fetch all roles."""

    return role_service.fetch_roles()


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
