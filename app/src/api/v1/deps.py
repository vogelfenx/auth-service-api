from typing import Annotated

from fastapi import Depends
from security.token import get_current_username_from_token
from security.models import TokenData

CurrentUserAnnotated = Annotated[
    TokenData, Depends(get_current_username_from_token)
]
