from fastapi import HTTPException, status


def valudate_admin_role(roles: list[str]):
    """Raise an error if no admin role in roles."""
    if "admin" not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only users with admin role can use this endpoint.",
        )
