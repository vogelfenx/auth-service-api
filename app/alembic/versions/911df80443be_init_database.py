"""Init database.

Revision ID: 911df80443be
Revises:
Create Date: 2023-06-12 12:07:16.483945

"""
from alembic import op
from datetime import datetime
from uuid import uuid4
from sqlalchemy import Column, ForeignKey, UniqueConstraint, Index
from sqlalchemy import VARCHAR, BOOLEAN, UUID, TIMESTAMP, INTEGER

from src.db.storage.partition_schema import USER_PARTITION_SCHEMA

# revision identifiers, used by Alembic.
revision = "911df80443be"
down_revision = None  # type: ignore
branch_labels = None  # type: ignore
depends_on = None  # type: ignore


def apply_user_partitions(part_dict: dict, del_flg: bool = False) -> None:
    for part_num in part_dict.keys():
        part_from = part_dict[part_num]['part_from']
        part_to = part_dict[part_num]['part_to']
        if not del_flg:
            sql_stmt = ("""CREATE TABLE IF NOT EXISTS "user_part_{0}" PARTITION OF "user" FOR VALUES FROM ({1}) TO ({2})"""
                        .format(part_num, part_from, part_to))
        else:
            sql_stmt = ("""DROP TABLE IF EXISTS user_part_{0}"""
                        .format(part_num)
                        )

        op.execute(sql_stmt)


def create_user_history_partitions():
    op.execute("""CREATE TABLE IF NOT EXISTS "user_history_smart" PARTITION OF "user_history" FOR VALUES IN ('smart')""")
    op.execute("""CREATE TABLE IF NOT EXISTS "user_history_mobile" PARTITION OF "user_history" FOR VALUES IN ('mobile')""")
    op.execute("""CREATE TABLE IF NOT EXISTS "user_history_web" PARTITION OF "user_history" FOR VALUES IN ('web')""")


def drop_user_history_partitions():
    op.execute("""DROP TABLE IF EXISTS user_history_smart""")
    op.execute("""DROP TABLE IF EXISTS user_history_mobile""")
    op.execute("""DROP TABLE IF EXISTS user_history_web""")


def upgrade() -> None:
    op.create_table(
        "user",
        Column("id", UUID, primary_key=True, default=uuid4),
        Column("username", VARCHAR, nullable=False),
        Column("email", VARCHAR, nullable=True),
        Column("full_name", VARCHAR, nullable=True),
        Column("disabled", BOOLEAN, nullable=False),
        Column("hashed_password", VARCHAR, nullable=False),
        Column("created", TIMESTAMP, default=datetime.now),
        Column(
            "modified", TIMESTAMP, default=datetime.now, onupdate=datetime.now
        ),
        Column("partition_char_num", INTEGER, primary_key=True, nullable=False),
        Index("idx_username", "username"),
        postgresql_partition_by="RANGE (partition_char_num)"
    )

    apply_user_partitions(USER_PARTITION_SCHEMA)

    op.create_table(
        "role",
        Column("id", UUID, primary_key=True, default=uuid4),
        Column("role", VARCHAR, nullable=False),
        Column("disabled", BOOLEAN, nullable=False),
        Column("description", VARCHAR, nullable=True),
        Column("created", TIMESTAMP, default=datetime.now),
        Column(
            "modified", TIMESTAMP, default=datetime.now, onupdate=datetime.now
        ),
        UniqueConstraint("role", name="uniq_role"),
        Index("idx_role", "role"),
    )

    op.create_table(
        "user_profile",
        Column("id", UUID, primary_key=True, default=uuid4),
        Column(
            "user_id",
            UUID,
            nullable=False,
        ),
        Column(
            "role_id",
            UUID,
            ForeignKey("role.id", ondelete="CASCADE"),
            nullable=False,
        ),
        Column("created", TIMESTAMP, default=datetime.now),
        Column(
            "modified", TIMESTAMP, default=datetime.now, onupdate=datetime.now
        )
    )

    op.create_table(
        "user_history",
        Column("id", UUID, primary_key=True, default=uuid4),
        Column(
            "user_id",
            UUID,
            nullable=False,
        ),
        Column("user_event", VARCHAR, nullable=True),
        Column("device_type", VARCHAR, primary_key=True, nullable=False),
        Column("created", TIMESTAMP, default=datetime.now),
        Column(
            "modified", TIMESTAMP, default=datetime.now, onupdate=datetime.now
        ),
        postgresql_partition_by="LIST (device_type)"
    )

    create_user_history_partitions()


def downgrade() -> None:
    op.drop_table("user")
    apply_user_partitions(USER_PARTITION_SCHEMA, del_flg=True)
    op.drop_table("role")
    op.drop_table("user_profile")
    op.drop_table("user_history")
    drop_user_history_partitions()
