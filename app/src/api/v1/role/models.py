from pydantic import BaseModel
from pydantic import Field
from uuid import UUID


class Role(BaseModel):
    """Role schema representation."""

    role: str
    description: str | None = None
    disabled: bool = False

    class Config:
        allow_population_by_field_name = True


class UserRole(BaseModel):
    """Assigned role with user"""
    role_id: UUID
    user_ud: UUID
