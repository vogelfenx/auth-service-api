from api.v2.auth.models import ResponseUser
from core.logger import get_logger
from db.storage.protocol import UserStorage

logger = get_logger(__name__)
logger.setLevel(level="INFO")


def assign(
    token: dict[str, str],
    user: dict[str, str],
    storage: UserStorage,
) -> ResponseUser:
    """Assign social account to auth service account."""
    email = user["email"]

    try:
        storage_user = storage.get_user(email)
    except:
        storage_user = None
        logger.info(
            "Not found user with name <%s>",
            email,
        )

    if storage_user:
        logger.info(
            "User <%s> has been already assigned to local user",
            email,
        )
    else:
        logger.info("Creating new user with email <%s>", email)
        storage.set_user(
            username=email,  # we use email as username
            email=email,
            full_name=user["name"],
            disabled=False,
            hashed_password=token["access_token"],
        )

        storage_user = storage.get_user(email)

    if not storage_user:
        raise ValueError("User has not been created")

    return ResponseUser(
        id=storage_user.id,
        username=storage_user.username,
        email=storage_user.email,
        full_name=storage_user.full_name,
    )
