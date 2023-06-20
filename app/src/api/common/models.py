from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import Query
from orjson import dumps, loads
from pydantic import BaseModel, Field


def orjson_dumps(v, *, default):
    """Decode bytes to unicode."""
    return dumps(v, default=default).decode()


class ConfigOrjsonMixin:
    """
    Mixin class to configure the orjson library for handling JSON files.

    Attributes:
        json_loads: A function to deserialize JSON data into Python objects.
        json_dumps: A function to serialize Python objects into JSON data.
    """

    json_loads = loads
    json_dumps = orjson_dumps


async def pagination_parameters(
    page_size: Annotated[
        int,
        Query(
            description="The size of the results to retrieve per page",
            ge=1,
            le=100,
        ),
    ] = 1,
    page_number: Annotated[
        int,
        Query(
            description="The page number to retrieve",
            ge=1,
        ),
    ] = 1,
):
    """Define common pagination parameters."""
    return {
        "page_size": page_size,
        "page_number": page_number,
    }
