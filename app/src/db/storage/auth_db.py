# В этом модуле предполагается реализовать модель хранения данных сервиса auth_api
# TODO: в будущем добавить абстрактные классы

from sqlalchemy import create_engine, select, update, insert
from sqlalchemy.orm import Session

from db.storage.models import BaseTable, User, Role, UserProfile, LoginHistory, Permission
from core.config import postgres_settings as pg_conf


class PgConnector:

    def __init__(self) -> None:
        self.engine = create_engine(f"postgresql+psycopg2://{'app'}:{'123qwe'}@{pg_conf.POSTGRES_HOST}/auth_database")
        BaseTable.metadata.create_all(self.engine)
        self.session = Session(self.engine)

    def get_user(self, username: str) -> User:
        stmt = select(User).where(User.username == username, User.disabled == False)
        try:
            return self.session.execute(stmt).all()[0]
        except Exception:
            self.session.rollback()
            raise Exception
        else:
            self.session.commit()

    def get_user_roles(self, username: str) -> list[Role]:
        stmt = select(Role).join(UserProfile, Role.id == UserProfile.role_id).join(User, User.id == UserProfile.user_id).where(User.username == username)
        try:
            return self.session.execute(stmt).all()
        except Exception:
            self.session.rollback()
            raise Exception
        else:
            self.session.commit()

    def get_user_permissions(self, username: str) -> list[Permission]:
        stmt = select(Permission).join(UserProfile, Permission.id == UserProfile.permission_id).join(User, UserProfile.user_id == User.id).where(User.username == username)
        try:
            return self.session.execute(stmt).all()
        except Exception:
            self.session.rollback()
            raise Exception
        else:
            self.session.commit()

    def set_password(self, username: str, h_password: str):
        stmt = update(User).where(User.username == username).values(hashed_password = h_password)
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
