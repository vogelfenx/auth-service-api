from pydantic import BaseModel
from uuid import UUID


class Role(BaseModel):
    """Role schema representation."""

    role: str
    description: str | None = None
    disabled: bool = False


class UserRole(BaseModel):
    """Assigned role with user schema representation."""

    role_id: UUID
    user_ud: UUID
