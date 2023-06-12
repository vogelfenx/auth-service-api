from functools import wraps

from api.v1.deps import CurrentUserAnnotated
from fastapi import HTTPException, status


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
            current_user: CurrentUserAnnotated,
            *args,
            **kwargs,
        ):
            current_roles = current_user.roles
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
