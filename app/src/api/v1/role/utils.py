from fastapi import Depends, HTTPException, status

from security.token import get_current_username_from_token
from functools import wraps
from fastapi import status, HTTPException


def validate_roles(
    roles: set[str],
    current_user=Depends(get_current_username_from_token),
):
    """
    Raise an error if user does not have one of roles (user must have at least one role from the list).

    Args:
        roles: a list of appropritiated roles.
    """

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
