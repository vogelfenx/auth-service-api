# В этом модуле предполагается реализовать модель хранения данных сервиса auth_api
# TODO: в будущем добавить абстрактные классы

from sqlalchemy import create_engine, select, update, insert, delete
from sqlalchemy.orm import Session
from db.storage import protocol
from logging import DEBUG
from uuid import UUID

from db.storage.models import (
    BaseTable,
    User,
    Role,
    UserProfile,
    LoginHistory,
    Permission,
)
from core.config import postgres_settings as pg_conf
from core.logger import get_logger
from security.hasher import Hasher

logger = get_logger(__name__, DEBUG)


class PgConnector:
    def __init__(self) -> None:
        self.engine = create_engine(
            f"postgresql+psycopg2://{'app'}:{'123qwe'}@{pg_conf.POSTGRES_HOST}/auth_database"
        )
        BaseTable.metadata.create_all(self.engine)
        self.session = Session(self.engine)

        self.role_connector = RoleConnector(self.session)

    def get_user(self, username: str) -> User:
        stmt = select(User).where(
            User.username == username, User.disabled == False
        )
        try:
            return self.session.execute(stmt).one()[0]
        except Exception:
            self.session.rollback()
            raise Exception
        else:
            self.session.commit()

    def get_user_roles(self, username: str) -> list[Role]:
        stmt = (
            select(Role)
            .join(UserProfile, Role.id == UserProfile.role_id)
            .join(User, User.id == UserProfile.user_id)
            .where(User.username == username)
        )
        try:
            return self.session.execute(stmt).all()
        except Exception:
            self.session.rollback()
            raise Exception
        else:
            self.session.commit()

    def get_user_permissions(self, username: str) -> list[Permission]:
        stmt = (
            select(Permission)
            .join(UserProfile, Permission.id == UserProfile.permission_id)
            .join(User, UserProfile.user_id == User.id)
            .where(User.username == username)
        )
        try:
            return self.session.execute(stmt).all()
        except Exception:
            self.session.rollback()
            raise Exception
        else:
            self.session.commit()

    def set_password(self, username: str, h_password: str):
        stmt = (
            update(User)
            .where(User.username == username)
            .values(hashed_password=h_password)
        )
        try:
            self.session.execute(stmt)
        except Exception:
            self.session.rollback()
            raise Exception
        else:
            self.session.commit()

    def set_user(self, **kwargs):
        stmt = insert(User).values(kwargs)
        try:
            self.session.execute(stmt)
        except Exception as e:
            self.session.rollback()
            print(e)
            raise e
        else:
            self.session.commit()

    def edit_user(self, username: str, **kwargs):
        stmt = update(User).where(User.username == username).values(kwargs)
        try:
            self.session.execute(stmt)
        except Exception:
            self.session.rollback()
            raise Exception
        else:
            self.session.commit()

    def close(self):
        self.session.close()

    def user_exists(self) -> bool:
        # TODO: Реализовать логику

        return False

    def authenticate_user(
        self,
        username: str,
        password: str,
    ):
        user = self.get_user(username)
        if not user:
            return False
        if not Hasher.verify_password(password, user.hashed_password):
            return False
        return user


class RoleConnector:
    """RoleConnector provides methods to work with roles."""

    def __init__(self, session) -> None:
        self.session = session

    def create_role(self, **kwargs) -> Role:
        """Create a new role."""
        logger.debug(f"Insert role: {kwargs}")

        created_role = None
        stmt = insert(Role).values(kwargs).returning(Role)
        try:
            created_role = self.session.execute(stmt).fetchone()[0]
            self.session.commit()
            logger.debug(f"The role was inserted successfully: {created_role}")
        except Exception as e:
            logger.error(e)
            self.session.rollback()
            raise e

        return created_role

    def delete_role(self, id: UUID) -> None:
        """Delete role by id."""
        logger.debug(f"Delete role with id: {id}")

        stmt = delete(Role).where(Role.id == id)
        try:
            self.session.execute(stmt)
            self.session.commit()
            logger.debug(f"Role with id {id} deleted successfully")
        except Exception as e:
            logger.error(e)
            self.session.rollback()
            raise e

    def edit_role(self, id: UUID, **kwargs) -> None:
        """Edit role by id."""
        logger.debug(f"Edit a role with id: {id}")

        stmt = update(Role).where(Role.id == id).values(**kwargs)
        try:
            self.session.execute(stmt)
            self.session.commit()
            logger.debug(f"Role with id {id} edited successfully")
        except Exception as e:
            logger.error(e)
            self.session.rollback()
            raise e

    def fetch_roles(self) -> list[Role]:
        """Fetch all roles."""
        logger.debug("Fetch all roles")

        stmt = select(Role)
        try:
            result = self.session.execute(stmt)
            roles = result.scalars().all()
        except Exception as e:
            logger.error(e)
            raise e

        return roles

    def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> UserProfile:
        """Assign a role to an user."""
        logger.debug(
            f"Assign role with id {role_id} to user with id {user_id}",
        )

        user_profile = UserProfile(
            user_id=user_id,
            role_id=role_id,
            # TODO: do we really need the permissions in UserRole?
            permission_id="eda0b04e-6fda-4d7f-b88d-5bfb1a66f697",
        )
        try:
            self.session.add(user_profile)
            self.session.flush()
            self.session.commit()
            logger.debug("Role assigned to user successfully")
        except Exception as e:
            logger.error(e)
            self.session.rollback()
            raise e

        return user_profile
