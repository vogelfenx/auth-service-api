from contextlib import asynccontextmanager

from api.v1.auth.default.routes import router as default_auth_v1
from api.v1.auth.yandex.routes import router as yandex_auth_v1
from api.v1.role.routes import router as role_v1
from core.config import api_settings, security_settings
from db.cache import dependency as cache_dependency
from db.cache.redis import RedisCache
from db.storage import dependency as storage_db
from db.storage.postgres import PostgresStorage
from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware import Middleware


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


origins = [
    "https://*.yandex.ru",
    "https://oauth.yandex.ru/authorize",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:80",
    "http://127.0.0.1",
    "http://localhost:8000",
    "http://localhost:80",
    "http://localhost",
]


middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=[
            "GET",
            "POST",
            "OPTIONS",
        ],
        allow_headers=[
            "*",
            "Authorization",
            "Content-Type",
            "Origin",
            "Access-Control-Allow-Origin",
            "Access-Control-Request-Headers",
        ],
        expose_headers=["*"],
    ),
    Middleware(
        SessionMiddleware,
        secret_key=security_settings.secret_key,
        max_age=60 * 60 * 24 * 7,
    ),
]


app = FastAPI(
    title=api_settings.project_name,
    docs_url="/api/openapi",
    openapi_url="/api/openapi.json",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
    middleware=middleware,
)

app.include_router(
    role_v1,
    prefix="/api/v1/role",
    tags=["role"],
    responses={404: {"description": "Not found"}},
)
app.include_router(
    default_auth_v1,
    prefix="/api/v1/auth/default",
    tags=["auth-default"],
    responses={404: {"description": "Not found"}},
)
app.include_router(
    yandex_auth_v1,
    prefix="/api/v1/auth/yandex",
    tags=["auth-yandex"],
    responses={404: {"description": "Not found"}},
)
