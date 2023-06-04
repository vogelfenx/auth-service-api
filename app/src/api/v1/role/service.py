from logging import DEBUG

from fastapi import Depends

from core.logger import get_logger
from db.storage.auth_db import PgConnector
from db.storage.dependency import get_storage
from db.storage.models import Role

logger = get_logger(__name__, DEBUG)


class RoleService:
    """Role Service class."""

    def __init__(self, storage):
        self.storage = storage

    def create_role(self, role) -> Role:
        """Create a new role."""
        role = self.storage.role_connector.create_role(**role.dict())
        return role

    def delete_role_by_id(self, role_id) -> None:
        """Delete a role by id."""
        self.storage.role_connector.delete_role(id=role_id)


def get_role_service(
    storage: PgConnector = Depends(get_storage),
) -> RoleService:
    """Use for set the dependency in api route."""
    return RoleService(storage)
