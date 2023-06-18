from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class BaseTable(DeclarativeBase):
    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
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
    __table_args__ = (
        UniqueConstraint("username", name="uniq_username"),
        Index("idx_username", "username"),
    )

    username: Mapped[str]
    email: Mapped[Optional[str]]
    full_name: Mapped[Optional[str]]
    disabled: Mapped[bool]
    hashed_password: Mapped[str]
    partition_char_num: Mapped[int]

    logins: Mapped[List["UserHistory"]] = relationship(cascade="all, delete")
    user_profile: Mapped[List["UserProfile"]] = relationship(
        cascade="all, delete"
    )

    def __repr__(self) -> str:
        return f"User(username={self.username}, disabled={self.disabled})"


class UserProfile(BaseTable):
    __tablename__ = "user_profile"

    user_id: Mapped[UUID] = mapped_column(ForeignKey("user.id"))
    role_id: Mapped[UUID] = mapped_column(ForeignKey("role.id"))


class Role(BaseTable):
    __tablename__ = "role"

    role: Mapped[str]
    disabled: Mapped[bool]
    description: Mapped[Optional[str]]

    roles_participant: Mapped[List["UserProfile"]] = relationship()

    __table_args__ = (
        UniqueConstraint("role", name="uniq_role"),
        Index("idx_role", "role"),
    )


class UserHistory(BaseTable):
    __tablename__ = "user_history"

    user_id: Mapped[UUID] = mapped_column(ForeignKey("user.id"))
    user_event: Mapped[Optional[str]]
    device_type: Mapped[str]

    def __repr__(self) -> str:
        return f"User event: {self.user_event}, timestamp: {self.created}"
