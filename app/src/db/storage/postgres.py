from logging import DEBUG
from uuid import UUID
from random import choice

from core.config import postgres_settings as pg_conf
from core.logger import get_logger
from db.storage.models import Role, User, UserHistory, UserProfile
from security.hasher import Hasher
from sqlalchemy import Row, create_engine, delete, insert, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql import exists
from sqlalchemy.sql.expression import literal_column

logger = get_logger(__name__, DEBUG)


class PostgresStorage:
    def __init__(self) -> None:
        url = "{driver}://{user}:{password}@{host}:{port}/{database}".format(
            driver="postgresql+psycopg2",
            user=pg_conf.postgres_user,
            password=pg_conf.postgres_password,
            host=pg_conf.postgres_host,
            port=pg_conf.postgres_port,
            database=pg_conf.postgres_db,
        )
        self.engine = create_engine(url)
        self.session = Session(self.engine)

    def get_user(self, username: str) -> User:
        """
        Fetch User class instance, build on retieved data from DB

        Args:
            username: name of user

        Returns:
            User class instance
        """
        stmt = select(User).where(
            User.username == username,  # type: ignore
            User.partition_char_num == ord(username[0]),  # type: ignore
            User.disabled == False,  # type: ignore
        )
        try:
            return self.session.execute(stmt).one()[0]
        except Exception:
            self.session.rollback()
            raise Exception
        finally:
            self.session.commit()

    def get_user_by_email(self, email: str) -> User:
        """
        Fetch User class instance, build on retieved data from DB

        Args:
            email: email of user

        Returns:
            User class instance
        """
        stmt = select(User).where(
            User.email == email,  # type: ignore
            User.partition_char_num == ord(email[0]),  # type: ignore
            User.disabled == False,  # type: ignore
        )
        try:
            return self.session.execute(stmt).one()[0]
        except Exception:
            self.session.rollback()
            raise Exception
        finally:
            self.session.commit()

    def get_user_roles(self, username: str) -> list[Role]:
        """
        Get roles for specified user.

        Args:
            username: name of specified user

        Returns:
            list of Role's class instances
        """
        stmt = (
            select(Role)
            .join(UserProfile, Role.id == UserProfile.role_id)  # type: ignore
            .join(User, User.id == UserProfile.user_id)
            .where(
                User.username == username,
                User.partition_char_num == ord(username[0]),
            )
        )
        try:
            roles = self.session.execute(stmt).all()
            return [row.Role for row in roles]

        except Exception:
            self.session.rollback()
            raise Exception
        finally:
            self.session.commit()

    def set_password(self, username: str, h_password: str) -> None:
        """
        Set password for specified user.

        Args:
            username: name of specified user
            h_password: hashed password to be set

        Returns:
            None
        """
        stmt = (
            update(User)
            .where(
                User.username == username,
                User.partition_char_num == ord(username[0]),
            )
            .values(hashed_password=h_password)
        )
        try:
            self.session.execute(stmt)
        except Exception:
            self.session.rollback()
            raise Exception
        finally:
            self.session.commit()

    def set_user(self, **kwargs) -> None:
        """
        Create user with any valid params.

        Args:
            kwargs: any valid User class attributes

        Returns:
            None
        """
        kwargs["partition_char_num"] = ord(kwargs["username"][0])
        stmt = insert(User).values(kwargs)
        try:
            self.session.execute(stmt)
        except Exception as e:
            self.session.rollback()
            logger.error(e)
            raise e
        finally:
            self.session.commit()

    def edit_user(self, username: str, **kwargs):
        """
        Update specified user's params.

        Args:
            username: name of specified user
            kwargs: any valid User class attributes

        Returns:
            None
        """
        kwargs["partition_char_num"] = ord(username[0])
        stmt = (
            update(User)
            .where(
                User.username == username,
                User.partition_char_num == ord(username[0]),
            )
            .values(kwargs)
        )
        try:
            self.session.execute(stmt)
        except Exception:
            self.session.rollback()
            raise Exception
        finally:
            self.session.commit()

    def user_exists(self, username: str) -> bool:
        """
        Check whether specified user exists

        Args:
            username: name of specified user

        Returns:
            bool user existence flag
        """
        stmt = select(
            exists(1).where(
                User.username == username,
                User.partition_char_num == ord(username[0]),
            )
        )  # type: ignore
        try:
            is_exists = self.session.execute(stmt).fetchone()[  # type: ignore
                0
            ]
        except Exception:
            self.session.rollback()
            raise Exception
        finally:
            self.session.commit()

        return is_exists

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> User | bool:
        """
        Authenticate specified user.

        Args:
            username: name of specified user
            password: password to be verified

        Returns:
            User | bool: User class instance if user have been authenticated.
            False if user haven't been authenticated.
        """
        user = self.get_user(username)
        if not user:
            return False
        if not Hasher.verify_password(password, user.hashed_password):
            return False
        return user

    def get_user_history(
        self, username: str, history_limit: int
    ) -> list[UserHistory]:
        """
        Get specified user's history.

        Args:
            username: name of specified user
            history_limit: limit of user's event history to be fetched

        Returns:
            list of UserHistory class instances
        """
        stmt = (
            select(UserHistory)
            .join(User, UserHistory.user_id == User.id)
            .where(
                User.username == username,
                User.partition_char_num == ord(username[0]),
            )
            .limit(history_limit)
        )

        return [row.UserHistory for row in self.session.execute(stmt).all()]

    def update_user_password(self, username: str, password: str):
        hashed_password = Hasher.get_password_hash(password=password)
        stmt = (
            update(User)
            .where(
                User.username == username,
                User.partition_char_num == ord(username[0]),
            )
            .values(hashed_password=hashed_password)
        )
        """
        Update specified user's password.

        Args:
            username: name of specified user
            password: new user password

        Returns:
            None
        """
        try:
            self.session.execute(stmt)
        except Exception:
            self.session.rollback()
            raise Exception
        finally:
            self.session.commit()

    def log_user_event(self, username: str, event_desc: str) -> None:
        """
        Log user event in log table.

        Args:
            username: name of specified user
            event_desc: event description

        Returns:
            None
        """
        event_desc_col = literal_column("'{0}'".format(event_desc)).label(
            "user_event"
        )  # type: ignore
        device_type = choice(["smart", "mobile", "web"])
        event_device_col = literal_column("'{0}'".format(device_type)).label(
            "device_type"
        )  # type: ignore
        select_stmt = select(
            User.id.label("user_id"), event_desc_col, event_device_col
        ).where(
            User.username == username,
            User.partition_char_num == ord(username[0]),
        )
        insert_stmt = insert(UserHistory).from_select(
            ["user_id", "user_event", "device_type"], select_stmt
        )
        try:
            self.session.execute(insert_stmt)
        except Exception as e:
            self.session.rollback()
            logger.error(e)
            raise e
        finally:
            self.session.commit()

    def create_role(self, **kwargs) -> Role:
        """Create a new role."""
        logger.debug("Insert role: {0}".format(kwargs))

        created_role = None
        stmt = insert(Role).values(kwargs).returning(Role)
        try:
            _created_role = self.session.execute(stmt).fetchone()
            if not isinstance(_created_role, Row):
                raise ValueError("Invalid role")

            created_role = _created_role[0]
            self.session.commit()
            logger.debug(
                "The role was inserted successfully: {0}".format(created_role)
            )
        except Exception as e:
            logger.error(e)
            self.session.rollback()
            raise e

        return created_role

    def get_role_by_name(self, role_name: str):
        """Get role by role name"""

        stmt = select(Role).where(
            Role.role == role_name,
            Role.disabled == False,
        )

        try:
            role = self.session.execute(stmt).one()[0]
        except Exception:
            self.session.rollback()
            raise Exception

        return role

    def delete_role(self, id: UUID) -> None:
        """Delete role by id."""
        logger.debug("Delete role with id: {0}".format(id))

        stmt = delete(Role).where(Role.id == id)
        try:
            self.session.execute(stmt)
            self.session.commit()
            logger.debug("Role with id {0} deleted successfully".format(id))
        except Exception as e:
            logger.error(e)
            self.session.rollback()
            raise e

    def edit_role(self, id: UUID, **kwargs) -> None:
        """Edit role by id."""
        logger.debug("Edit a role with id: {0}".format(id))

        stmt = update(Role).where(Role.id == id).values(**kwargs)
        try:
            self.session.execute(stmt)
            self.session.commit()
            logger.debug("Role with id {0} edited successfully".format(id))
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

        return roles  # type: ignore

    def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> UserProfile:
        """Assign a role to an user."""
        logger.debug(
            "Assign role with id {0} to user with id {1}".format(
                role_id, user_id
            ),
        )

        user_profile = UserProfile(
            user_id=user_id,
            role_id=role_id,
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

    def close(self):
        """Close active database session"""
        self.session.close()
