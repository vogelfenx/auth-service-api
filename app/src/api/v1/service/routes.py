from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query

router = APIRouter()


@router.get("/signin")
async def signin():
    """Doc."""

    return {"message": "This is signin."}, HTTPStatus.OK
