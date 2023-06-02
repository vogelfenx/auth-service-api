import os

from logging import config as logging_config
from pydantic import BaseSettings

from core.logger import LOGGING

# Применяем настройки логирования
logging_config.dictConfig(LOGGING)


class CommonSettings(BaseSettings):
    """Общий конфиг-класс."""

    # Корень проекта
    file_path = os.path.abspath(__file__)
    dir_path = os.path.dirname(file_path)
    BASE_DIR = os.path.dirname(dir_path)

    class Config:
        env_file = "../.env"
        case_sensitive = False


class ApiSettings(CommonSettings):
    """Класс с настройками FastAPI."""

    # Название проекта. Используется в Swagger-документации
    PROJECT_NAME: str

    # Шаблон для UUID
    UUID_REGEXP = r"[\w\d]{8}-[\w\d]{4}-[\w\d]{4}-[\w\d]{4}-[\w\d]{12}"


class PostgresSettings(CommonSettings):
    """Класс с настройками Postgres."""

    POSTGRES_HOST: str
    POSTGRES_PORT: int


class RedisSettings(CommonSettings):
    """Класс с настройками Redis."""

    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_EXPIRE: int = 60 * 5  # 5 min


class SecuritySettings(CommonSettings):
    """Класс с настройками Redis."""

    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_MINUTES: int


api_settings = ApiSettings()  # type: ignore
postgres_settings = PostgresSettings()  # type: ignore
redis_settings = RedisSettings()  # type: ignore
security_settings = SecuritySettings()  # type: ignore
