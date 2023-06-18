from functools import wraps

from fastapi import HTTPException, status

from security.models import TokenData


def role_required(
    roles: set[str],
):
    """
    Raise an error if user does not have one of roles (user must have at least one role from the list).

    Args:
        roles: a list of appropritiated roles.
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(
            *args,
            **kwargs,
        ):
            current_user = kwargs.get("current_user")
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid user",
                )
            current_roles = TokenData.parse_obj(current_user).roles
            if len(roles.intersection(current_roles)) <= 0:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User must be included in at least one role: {roles}.".format(
                        roles=",".join(roles)
                    ),
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator
