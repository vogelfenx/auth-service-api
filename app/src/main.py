from contextlib import asynccontextmanager

from api.v1.auth.routes import router as auth_v1
from api.v1.role.routes import router as role_v1
from api.v2.auth.default.routes import router as default_auth_v2
from api.v2.auth.google.routes import router as google_auth_v2
from api.v2.auth.yandex.routes import router as yandex_auth_v2
from core.config import api_settings, security_settings
from db.cache import dependency as cache_dependency
from db.cache.redis import RedisCache
from db.storage import dependency as storage_db
from db.storage.postgres import PostgresStorage
from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware


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

origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=security_settings.secret_key,
    max_age=60 * 60 * 24 * 7,
)
app.include_router(
    role_v1,
    prefix="/api/v1/role",
    tags=["role-v1"],
    responses={404: {"description": "Not found"}},
)
app.include_router(
    auth_v1,
    prefix="/api/v1/auth",
    tags=["auth-v1"],
    responses={404: {"description": "Not found"}},
)
app.include_router(
    default_auth_v2,
    prefix="/api/v2/auth/default",
    tags=["auth-default-v2"],
    responses={404: {"description": "Not found"}},
)
app.include_router(
    yandex_auth_v2,
    prefix="/api/v2/auth/yandex",
    tags=["auth-yandex-v2"],
    responses={404: {"description": "Not found"}},
)
app.include_router(
    google_auth_v2,
    prefix="/api/v2/auth",
    tags=["auth-v2"],
    responses={404: {"description": "Not found"}},
)
