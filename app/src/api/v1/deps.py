from typing import Annotated

from fastapi import Depends
from security.models import TokenData
from security.token import get_current_username_from_token

CurrentUserAnnotated = Annotated[
    TokenData, Depends(get_current_username_from_token)
]
