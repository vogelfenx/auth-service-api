import typing


class User(typing.Protocol):
    pass


class Role(typing.Protocol):
    pass


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
