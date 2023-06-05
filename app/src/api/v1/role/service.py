from logging import DEBUG
from uuid import UUID

from fastapi import Depends

from core.logger import get_logger
from db.storage.protocol import Storage
from db.storage.dependency import get_storage

from .models import Role, UserRole

logger = get_logger(__name__, DEBUG)


class RoleService:
    """Role Service class."""

    def __init__(self, storage: Storage):
        self.storage = storage

    def create_role(self, role: Role) -> Role:
        """Create a new role."""
        role = self.storage.role_connector.create_role(**role.dict())
        return role

    def delete_role_by_id(self, role_id: UUID) -> None:
        """Delete a role by id."""
        self.storage.role_connector.delete_role(id=role_id)

    def edit_role_by_id(self, role_id: UUID, role: Role) -> None:
        """Edit a role by id."""
        self.storage.role_connector.edit_role(id=role_id, **role.dict())

    def fetch_roles(self) -> list[Role]:
        """Fetch all roles from a source."""
        roles = self.storage.role_connector.fetch_roles()
        roles = [Role(**role.__dict__) for role in roles]
        return roles

    def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> UserRole:
        """Assign a role to an user."""
        user_role = self.storage.role_connector.assign_role_to_user(
            user_id=user_id,
            role_id=role_id,
        )
        return user_role


def get_role_service(
    storage: Storage = Depends(get_storage),
) -> RoleService:
    """Use for set the dependency in api route."""
    return RoleService(storage)
