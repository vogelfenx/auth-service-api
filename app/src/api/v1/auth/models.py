from email.policy import default
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
    username: Annotated[
        str,
        Query(description="Uniq username"),
    ]
    email: EmailStr | None = None
    full_name: Annotated[
        str | None,
        Query(description="User's full name"),
    ] = None
    disabled: Annotated[
        bool,
        Query(description="Is the user activated flag"),
    ] = False


class ResponseUser(BaseModel):
    id: UUID
    username: Annotated[
        str,
        Query(description="Uniq username"),
    ]
    email: EmailStr | None = None
    full_name: Annotated[
        str | None,
        Query(description="User's full name"),
    ] = None
    disabled: Annotated[
        bool,
        Query(description="Is the user activated flag"),
    ] = False


PasswordAnnotated = Annotated[Password, Depends()]
UserAnnotated = Annotated[User, Depends()]
