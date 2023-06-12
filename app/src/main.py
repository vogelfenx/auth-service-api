from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import ORJSONResponse

from api.v1.auth.routes import router as auth_v1
from api.v1.role.routes import router as role_v1
from core.config import api_settings
from db.cache import dependency as cache_dependency
from db.cache.redis import RedisCache
from db.storage import dependency as storage_db
from db.storage.postgres import PostgresStorage


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage dependencies on app startup and shutdown."""
    storage_db.storage = PostgresStorage()
    cache_dependency.cache = RedisCache()
    yield
    if storage_db.storage:
        storage_db.storage.close()
    if cache_dependency.cache:
        await cache_dependency.cache.close()

app = FastAPI(
    title=api_settings.project_name,
    docs_url="/api/openapi",
    openapi_url="/api/openapi.json",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

app.include_router(
    role_v1,
    prefix="/api/v1/role",
    tags=["role"],
    responses={404: {"description": "Not found"}},
)
app.include_router(
    auth_v1,
    prefix="/api/v1/auth",
    tags=["auth"],
    responses={404: {"description": "Not found"}},
)
