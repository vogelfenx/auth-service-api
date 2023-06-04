import typing


class User(typing.Protocol):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    hashed_password: str


class Role(typing.Protocol):
    """Role protocol representation."""


class Permission(typing.Protocol):
    pass


class Storage(typing.Protocol):
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

    def close(self):
        ...

    def user_exists(self) -> bool:
        ...


class RoleStorage(typing.Protocol):
    def create_role(self) -> Role:
        ...

    def delete_role(self, id) -> None:
        ...
