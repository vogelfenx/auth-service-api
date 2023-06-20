import typer
from db.storage.postgres import PostgresStorage
from security.hasher import Hasher

app = typer.Typer()


@app.command()
def createadmin(username: str, password: str):
    """Create a new superuser with admin role."""

    if pg_storage.user_exists(username):
        raise Exception("Username already exists!")

    hashed_password = Hasher.get_password_hash(password=password)
    user = pg_storage.create_user(
        username=username,
        disabled=False,
        hashed_password=hashed_password,
    )

    user = pg_storage.get_user(
        username=username,
    )

    try:
        admin_role = pg_storage.create_role(
            role="admin",
            disabled=False,
        )
    except Exception:
        print("Admin Role already exists, continue ")
        admin_role = pg_storage.get_role_by_name(role_name="admin")

    pg_storage.assign_role_to_user(
        user.id,
        admin_role.id,
    )


@app.command()
def changeadmin(username: str, password: str):

if __name__ == "__main__":
    pg_storage = PostgresStorage()
    app()
