from fastapi import Depends, HTTPException, status
<<<<<<< HEAD
from api.v1.deps import CurrentUserAnnotated
from security.models import TokenData
=======
>>>>>>> 3e99acb218f819f10a96ebd38d1b317c4692ad86

from security.token import get_current_username_from_token
from functools import wraps
from fastapi import status, HTTPException


<<<<<<< HEAD
def role_required(
    roles: set[str],
=======
def validate_roles(
    roles: set[str],
    current_user=Depends(get_current_username_from_token),
>>>>>>> 3e99acb218f819f10a96ebd38d1b317c4692ad86
):
    """
    Raise an error if user does not have one of roles (user must have at least one role from the list).

    Args:
        roles: a list of appropritiated roles.
    """

<<<<<<< HEAD
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
=======
    def _validate_roles(func):
        current_roles = current_user.roles
        if len(roles.intersection(current_roles)) <= 0:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User must be included in at least one role: {roles}.".format(
                    roles=",".join(roles)
                ),
            )

        @wraps(func)
        def pn(*args, **kwargs):
            return func(*args, **kwargs)

        return pn

    return _validate_roles
>>>>>>> 3e99acb218f819f10a96ebd38d1b317c4692ad86
