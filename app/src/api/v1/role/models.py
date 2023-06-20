from typing import Annotated
from uuid import UUID

from fastapi import Query
from pydantic import BaseModel


class CreateRole(BaseModel):
    """Role schema for Create and Update forms."""

    role: Annotated[str, Query(description="Role name")]
    description: Annotated[
        str | None,
        Query(
            description="Role description",
        ),
    ] = None
    disabled: Annotated[
        bool,
        Query(
            description="Is Role disabled flag",
        ),
    ] = False


class ResponseRole(BaseModel):
    """Role schema for Response."""

    id: UUID
    role: Annotated[str, Query(description="Role name")]
    description: Annotated[
        str | None,
        Query(
            description="Role description",
        ),
    ] = None
    disabled: Annotated[
        bool,
        Query(
            description="Is Role disabled flag",
        ),
    ] = False


class UserRole(BaseModel):
    """Assigned role with user schema representation."""

    role_id: Annotated[UUID, Query(description="Role's ID to be assigned")]
    user_ud: Annotated[
        UUID,
        Query(
            description="User's ID qualified for the role",
        ),
    ]
