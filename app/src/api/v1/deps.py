from typing import Annotated

from db.storage.protocol import StorageUserModel
from fastapi import Depends
from security.token import get_current_username_from_token

CurrenUserAnnotated = Annotated[
    StorageUserModel, Depends(get_current_username_from_token)
]
