"""
В логгере настраивается логгирование uvicorn-сервера.
Про логирование в Python можно прочитать в документации.
https://docs.python.org/3/howto/logging.html.
https://docs.python.org/3/howto/logging-cookbook.html.
Применение настроек происходит в конфиге.
logging.config.dictConfig(LOGGING).
"""
import logging
import logging.config

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {"format": LOG_FORMAT},
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(message)s",
            "use_colors": None,
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": "%(levelprefix)s %(client_addr)s -\
                  '%(request_line)s' %(status_code)s",
        },
    },
    "handlers": {
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        "": {
            "handlers": [
                "console",
            ],
            "level": "INFO",
        },
        "uvicorn.error": {
            "level": "INFO",
        },
        "uvicorn.access": {
            "handlers": ["access"],
            "level": "INFO",
            "propagate": False,
        },
    },
    "root": {
        "level": "INFO",
        "formatter": "verbose",
        "handlers": [
            "console",
        ],
    },
}


def get_logger(name: str, logging_level: int | str = logging.INFO):
    """Return default logger."""
    logger = logging.getLogger(name)
    logger.setLevel(logging_level)
    return logger
