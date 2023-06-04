from pydantic import BaseModel
from pydantic import Field


class Role(BaseModel):
    """Role schema representation."""

    role: str
    description: str | None = None
    disabled: bool = False

    class Config:
        allow_population_by_field_name = True
