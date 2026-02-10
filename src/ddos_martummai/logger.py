import logging
import os
from logging.handlers import TimedRotatingFileHandler

from rich.logging import RichHandler

logger = logging.getLogger("ddos-martummai")


def get_console_logger(level=logging.INFO):
    if logger.hasHandlers():
        return logger

    console_handler = RichHandler(rich_tracebacks=True, markup=True)

    logging.basicConfig(
        level=level, format="%(message)s", datefmt="[%X]", handlers=[console_handler]
    )
    return logger


def attach_file_logging(log_file_path: str):
    try:
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

        file_handler = TimedRotatingFileHandler(
            filename=log_file_path,
            when="midnight",
            interval=1,
            backupCount=90,
            encoding="utf-8",
        )
        file_formatter = logging.Formatter(
            "%(asctime)s - [%(filename)s:%(lineno)d] %(funcName)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        file_handler.suffix = "%Y-%m-%d"

        logger.addHandler(file_handler)
        logger.info(f"File logging enabled at: {log_file_path}")

    except Exception as e:
        logger.error(f"Failed to setup file logging: {e}")
