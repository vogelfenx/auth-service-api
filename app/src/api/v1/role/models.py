from pydantic import BaseModel
from uuid import UUID


class CreateRole(BaseModel):
    """Role schema for Create and Update forms."""

    role: str
    description: str | None = None
    disabled: bool = False


class ResponseRole(BaseModel):
    """Role schema for Response."""

    id: UUID
    role: str
    description: str | None = None
    disabled: bool = False


class UserRole(BaseModel):
    """Assigned role with user schema representation."""

    role_id: UUID
    user_ud: UUID
