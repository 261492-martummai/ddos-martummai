import logging
import os
from logging.handlers import TimedRotatingFileHandler

from rich.logging import RichHandler


def setup_logger(log_file_path: str, level=logging.INFO):
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

    console_handler = RichHandler(rich_tracebacks=True, markup=True)

    # 1. Base Logger Config
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[console_handler, file_handler],
    )

    return logging.getLogger("ddos-martummai")
