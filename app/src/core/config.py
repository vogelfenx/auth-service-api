import os
from logging import config as logging_config

from core.logger import LOGGING
from pydantic import BaseSettings

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
    project_name: str

    # Шаблон для UUID
    uuid_regexp = r"[\w\d]{8}-[\w\d]{4}-[\w\d]{4}-[\w\d]{4}-[\w\d]{12}"


class PostgresSettings(CommonSettings):
    """Класс с настройками Postgres."""

    postgres_host: str
    postgres_port: int
    postgres_user: str
    postgres_password: str
    postgres_db: str


class RedisSettings(CommonSettings):
    """Класс с настройками Redis."""

    redis_host: str
    redis_port: int
    redis_expire: int = 60 * 5  # 5 min


class SecuritySettings(CommonSettings):
    """Класс с настройками Redis."""

    secret_key: str
    algorithm: str
    access_token_expire_minute: int
    refresh_token_expire_minute: int


api_settings = ApiSettings()  # type: ignore
postgres_settings = PostgresSettings()  # type: ignore
redis_settings = RedisSettings()  # type: ignore
security_settings = SecuritySettings()  # type: ignore
