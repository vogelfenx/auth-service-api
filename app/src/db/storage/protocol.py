import typing
from uuid import UUID


class User(typing.Protocol):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    hashed_password: str


class Role(typing.Protocol):
    """Role protocol representation."""


class UserProfile(typing.Protocol):
    """Assigned role to user"""


class Permission(typing.Protocol):
    pass


class Storage(typing.Protocol):
    def close(self) -> None:
        ...


class RoleStorage(typing.Protocol):
    def create_role(self, **kwargs) -> Role:
        ...

    def delete_role(self, id: UUID) -> None:
        ...

    def edit_role(self, id: UUID, **kwargs) -> None:
        ...

    def fetch_roles(self) -> list[Role]:
        ...

    def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> UserProfile:
        ...


class UserStorage(typing.Protocol):
    def get_user(self, username: str) -> User:
        ...

    def get_user_roles(self, username: str) -> list[Role]:
        ...

    def get_user_permissions(self, username: str) -> list[Permission]:
        ...

    def set_password(self, username: str, h_password: str):
        ...

    def set_user(self, **kwargs):
        ...

    def edit_user(self, username: str, **kwargs):
        ...

    def user_exists(self) -> bool:
        ...
