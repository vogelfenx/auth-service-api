from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from core.config import api_settings
from api.v1.role.routes import router as role_v1
from api.v1.auth.routes import router as auth_v1
from db.storage.postgres import PostgresStorage
from db.cache.redis import RedisCache
from db.storage import dependency as storage_db
from db.cache import dependency as cache_dependency

app = FastAPI(
    title=api_settings.PROJECT_NAME,
    docs_url="/api/openapi",
    openapi_url="/api/openapi.json",
    default_response_class=ORJSONResponse,
)


@app.on_event("startup")
async def startup():
    """Start dependency."""
    storage_db.storage = PostgresStorage()
    cache_dependency.cache = RedisCache()


@app.on_event("shutdown")
async def shutdown():
    """Stop dependency."""

    if storage_db.storage:
        storage_db.storage.close()

    if cache_dependency.cache:
        await cache_dependency.cache.close()


# Теги указываем для удобства навигации по документации
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
