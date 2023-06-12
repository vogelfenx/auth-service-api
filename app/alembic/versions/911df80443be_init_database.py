"""Init database

Revision ID: 911df80443be
Revises:
Create Date: 2023-06-12 12:07:16.483945

"""
from alembic import op
from datetime import datetime
from uuid import uuid4
from sqlalchemy import Column, ForeignKey, UniqueConstraint, Index
from sqlalchemy import VARCHAR, BOOLEAN, UUID, TIMESTAMP


# revision identifiers, used by Alembic.
revision = '911df80443be'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user",
        Column('id', UUID, primary_key=True, default=uuid4),
        Column('username', VARCHAR, nullable=False),
        Column('email', VARCHAR, nullable=True),
        Column('full_name', VARCHAR, nullable=True),
        Column('disabled', BOOLEAN, nullable=False),
        Column('hashed_password', VARCHAR, nullable=False),
        Column('created', TIMESTAMP, default=datetime.now),
        Column('modified', TIMESTAMP, default=datetime.now, onupdate=datetime.now),
        UniqueConstraint("username", name="uniq_username"),
        Index("idx_username", "username")
    )

    op.create_table(
        "role",
        Column('id', UUID, primary_key=True, default=uuid4),
        Column('role', VARCHAR, nullable=False),
        Column('disabled', BOOLEAN, nullable=False),
        Column('description', VARCHAR, nullable=True),
        Column('created', TIMESTAMP, default=datetime.now),
        Column('modified', TIMESTAMP, default=datetime.now, onupdate=datetime.now),
        UniqueConstraint("role", name="uniq_role"),
        Index("idx_role", "role")
    )

    op.create_table(
        "user_profile",
        Column('id', UUID, primary_key=True, default=uuid4),
        Column('user_id', UUID, ForeignKey("user.id", ondelete="CASCADE"), nullable=False),
        Column('role_id', UUID, ForeignKey("role.id", ondelete="CASCADE"), nullable=False),
        Column('created', TIMESTAMP, default=datetime.now),
        Column('modified', TIMESTAMP, default=datetime.now, onupdate=datetime.now)
    )

    op.create_table(
        "user_history",
        Column('id', UUID, primary_key=True, default=uuid4),
        Column('user_id', UUID, ForeignKey("user.id", ondelete="CASCADE"), nullable=False),
        Column('user_event', VARCHAR, nullable=True),
        Column('created', TIMESTAMP, default=datetime.now),
        Column('modified', TIMESTAMP, default=datetime.now, onupdate=datetime.now)
    )


def downgrade() -> None:
    op.drop_table("user")
    op.drop_table("role")
    op.drop_table("user_profile")
    op.drop_table("user_history")
