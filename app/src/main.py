from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from core.config import api_settings
from api.v1.service.routes import router as service_v1


app = FastAPI(
    title=api_settings.PROJECT_NAME,
    docs_url="/api/openapi",
    openapi_url="/api/openapi.json",
    default_response_class=ORJSONResponse,
)


@app.on_event("startup")
async def startup():
    """Start dependency."""
    pass


@app.on_event("shutdown")
async def shutdown():
    """Stop dependency."""
    pass


# Теги указываем для удобства навигации по документации
app.include_router(
    service_v1,
    prefix="/api/v1/service",
    tags=["service"],
    responses={404: {"description": "Not found"}},
)
