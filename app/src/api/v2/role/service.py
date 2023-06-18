from logging import DEBUG
from uuid import UUID

from core.logger import get_logger
from db.storage.dependency import get_storage
from db.storage.protocol import RoleStorage, StorageRoleModel
from fastapi import Depends

from .models import CreateRole, ResponseRole, UserRole

logger = get_logger(__name__, DEBUG)


class RoleService:
    """Role Service class."""

    def __init__(self, storage: RoleStorage):
        self.storage = storage

    def create_role(self, role: CreateRole) -> StorageRoleModel:
        """Create a new role."""
        role = self.storage.create_role(**role.dict())
        return role

    def delete_role_by_id(self, role_id: UUID) -> None:
        """Delete a role by id."""
        self.storage.delete_role(id=role_id)

    def edit_role_by_id(self, role_id: UUID, role: CreateRole) -> None:
        """Edit a role by id."""
        self.storage.edit_role(id=role_id, **role.dict())

    def fetch_roles(self) -> list[CreateRole]:
        """Fetch all roles from a source."""
        roles = self.storage.fetch_roles()
        roles = [ResponseRole(**role.__dict__) for role in roles]
        return roles

    def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> UserRole:
        """Assign a role to an user."""
        user_role = self.storage.assign_role_to_user(
            user_id=user_id,
            role_id=role_id,
        )
        return user_role


def get_role_service(
    storage: RoleStorage = Depends(get_storage),
) -> RoleService:
    """Use for set the dependency in api route."""
    return RoleService(storage)
