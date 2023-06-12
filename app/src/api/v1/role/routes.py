from logging import DEBUG
from typing import Annotated
from uuid import UUID
from api.v1.deps import CurrentUserAnnotated

from core.logger import get_logger
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from .models import CreateRole, ResponseRole
from .service import RoleService, get_role_service
from .utils import role_required

logger = get_logger(__name__, DEBUG)

router = APIRouter()


@router.post(
    "/",
    status_code=status.HTTP_200_OK,
    summary="Create a new role",
    response_description="Created role's ID.",
)
@role_required(roles={"admin"})
async def create_role(
    current_user: CurrentUserAnnotated,
    role: CreateRole = Depends(CreateRole),
    role_service: RoleService = Depends(get_role_service),
) -> dict[str, str]:
    """Create a new role."""
    try:
        created_role = role_service.create_role(role=role)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return {"uuid": str(created_role.id)}


@router.delete(
    "/{role_id}",
    summary="Delete a role",
)
@role_required(roles={"admin"})
async def delete_role(
    current_user: CurrentUserAnnotated,
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


@router.put(
    "/{role_id}",
    summary="Edit a role",
)
@role_required(roles={"admin"})
async def edit_role(
    current_user: CurrentUserAnnotated,
    role_id: Annotated[UUID, Path(description="ID of the role to edit")],
    role: CreateRole = Depends(CreateRole),
    role_service: RoleService = Depends(get_role_service),
):
    """Edit a role by id."""
    try:
        role_service.edit_role_by_id(role_id=role_id, role=role)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@router.get(
    "/all",
    summary="Get all roles",
    response_model=list[ResponseRole],
)
@role_required(roles={"admin"})
async def fetch_roles(
    current_user: CurrentUserAnnotated,
    role_service: RoleService = Depends(get_role_service),
):
    """Get all roles."""
    return role_service.fetch_roles()


@router.post(
    "/assign",
    summary="Assign a role to a user.",
    status_code=status.HTTP_201_CREATED,
)
@role_required(roles={"admin"})
async def assign_role(
    current_user: CurrentUserAnnotated,
    role_id: Annotated[UUID, Query(description="A role id.")],
    user_id: Annotated[UUID, Query(description="A user id.")],
    role_service: RoleService = Depends(get_role_service),
):
    """Assign the given role to the given user."""
    _ = role_service.assign_role_to_user(
        role_id=role_id,
        user_id=user_id,
    )
