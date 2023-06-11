from typing import Annotated
from uuid import UUID
from fastapi import (
    Depends,
    Path,
    Query,
)
from pydantic import BaseModel, Field, EmailStr, SecretStr


class Password(BaseModel):
    password: SecretStr


class User(Password, BaseModel):
    username: str
    email: EmailStr | None
    full_name: str | None
    disabled: bool = False


class ResponseUser(BaseModel):
    id: UUID
    username: str
    email: EmailStr | None = None
    full_name: str | None = None
    disabled: bool = False


PasswordAnnotated = Annotated[Password, Depends()]
UserAnnotated = Annotated[User, Depends()]
