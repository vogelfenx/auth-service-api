from logging import DEBUG, INFO
from typing import Annotated
from uuid import UUID
from api.v1.deps import CurrentUserAnnotated

from core.logger import get_logger
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from .models import CreateRole, ResponseRole, UserRole
from .utils import valudate_admin_role
from .service import RoleService, get_role_service

logger = get_logger(__name__, DEBUG)

router = APIRouter()


@router.post(
    "/",
    status_code=status.HTTP_200_OK,
)
async def create_role(
    current_user: CurrentUserAnnotated,
    role: CreateRole = Depends(CreateRole),
    role_service: RoleService = Depends(get_role_service),
) -> dict[str, UUID]:
    """Create a new role."""

    valudate_admin_role(current_user.roles)
    try:
        created_role = role_service.create_role(role=role)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return {"uuid": created_role.id}


@router.delete("/{role_id}")
async def delete_role(
    current_user: CurrentUserAnnotated,
    role_id: Annotated[UUID, Path(description="ID of the role to delete")],
    role_service: RoleService = Depends(get_role_service),
) -> None:
    """Delete a role by id."""
    valudate_admin_role(current_user.roles)

    try:
        role_service.delete_role_by_id(role_id=role_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@router.put("/{role_id}")
async def edit_role(
    current_user: CurrentUserAnnotated,
    role_id: Annotated[UUID, Path(description="ID of the role to edit")],
    role: CreateRole = Depends(CreateRole),
    role_service: RoleService = Depends(get_role_service),
):
    """Edit a role by id."""
    valudate_admin_role(current_user.roles)

    try:
        role_service.edit_role_by_id(role_id=role_id, role=role)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@router.get("/all", response_model=list[ResponseRole])
async def fetch_roles(
    current_user: CurrentUserAnnotated,
    role_service: RoleService = Depends(get_role_service),
):
    """Fetch all roles."""

    return role_service.fetch_roles()


@router.post(
    "/assign",
    status_code=status.HTTP_201_CREATED,
)
async def assign_role(
    current_user: CurrentUserAnnotated,
    role_id: Annotated[UUID, Query(description="A role id.")],
    user_id: Annotated[UUID, Query(description="A user id.")],
    role_service: RoleService = Depends(get_role_service),
):
    """Assign a role to a user."""
    valudate_admin_role(current_user.roles)

    _ = role_service.assign_role_to_user(
        role_id=role_id,
        user_id=user_id,
    )


@router.post(
    "/validate/{user_id}",
    status_code=status.HTTP_200_OK,
)
async def validate():
    """Validate that a user has permissions."""
    pass