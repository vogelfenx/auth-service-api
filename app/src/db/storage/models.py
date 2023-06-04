from uuid import uuid4, UUID
from typing import Optional, List

from sqlalchemy.orm import Mapped, mapped_column, relationship, DeclarativeBase
from sqlalchemy import ForeignKey

from datetime import datetime


class BaseTable(DeclarativeBase):
    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=UUID(uuid4().hex),
    )
    created: Mapped[datetime] = mapped_column(
        default=datetime.now,
    )
    modified: Mapped[datetime] = mapped_column(
        default=datetime.now,
        onupdate=datetime.now,
    )


class User(BaseTable):
    __tablename__ = "user"

    username: Mapped[Optional[str]]
    email: Mapped[Optional[str]]
    full_name: Mapped[Optional[str]]
    disabled: Mapped[bool]
    hashed_password: Mapped[str]

    logins: Mapped[List["LoginHistory"]] = relationship(cascade="all, delete")
    user_profile: Mapped[List["UserProfile"]] = relationship(
        cascade="all, delete"
    )

    def __repr__(self) -> str:
        return f"User(username={self.username}, disabled={self.disabled})"


class UserProfile(BaseTable):
    __tablename__ = "user_profile"

    user_id: Mapped[UUID] = mapped_column(ForeignKey("user.id"))
    role_id: Mapped[UUID] = mapped_column(ForeignKey("role.id"))
    permission_id: Mapped[UUID] = mapped_column(ForeignKey("permission.id"))


class Role(BaseTable):
    __tablename__ = "role"

    role: Mapped[str]
    disabled: Mapped[bool]
    description: Mapped[Optional[str]]

    roles_participant: Mapped[List["UserProfile"]] = relationship()

    def __repr__(self) -> str:
        return f"Role(name={self.role}, disabled={self.disabled})"


class Permission(BaseTable):
    __tablename__ = "permission"

    permission_name: Mapped[str]
    disabled: Mapped[bool]
    description: Mapped[Optional[str]]

    permission_participant: Mapped[List["UserProfile"]] = relationship()

    def __repr__(self) -> str:
        return f"Permission(name={self.permission_name}, disabled={self.disabled})"


class LoginHistory(BaseTable):
    __tablename__ = "login_history"

    user_id: Mapped[UUID] = mapped_column(ForeignKey("user.id"))
    disabled: Mapped[bool]
