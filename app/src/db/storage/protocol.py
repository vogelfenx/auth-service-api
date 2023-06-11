import typing
from uuid import UUID


class StorageUserModel(typing.Protocol):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    hashed_password: str


class StorageRoleModel(typing.Protocol):
    id: str
    """Role protocol representation."""


class StorageUserProfileModel(typing.Protocol):
    """Assigned role to user"""


class StoragePermissionModel(typing.Protocol):
    pass


class Storage(typing.Protocol):
    def close(self) -> None:
        ...


class RoleStorage(typing.Protocol):
    def create_role(self, **kwargs) -> StorageRoleModel:
        ...

    def delete_role(self, id: UUID) -> None:
        ...

    def edit_role(self, id: UUID, **kwargs) -> None:
        ...

    def fetch_roles(self) -> list[StorageRoleModel]:
        ...

    def assign_role_to_user(
        self, user_id: UUID, role_id: UUID
    ) -> StorageUserProfileModel:
        ...


class UserStorage(typing.Protocol):
    def get_user(self, username: str) -> StorageUserModel:
        ...

    def get_user_roles(self, username: str) -> list[StorageRoleModel]:
        ...

    # def get_user_permissions(
    #     self, username: str
    # ) -> list[StoragePermissionModel]:
    #     ...

    def set_password(self, username: str, h_password: str):
        ...

    def set_user(self, **kwargs):
        ...

    def edit_user(self, username: str, **kwargs):
        ...

    def user_exists(self) -> bool:
        ...

    def log_user_event(self, username: str, event_desc: str) -> None:
        ...

    def authenticate_user(
        self, username: str, password: str
    ) -> StorageUserModel:
        ...
