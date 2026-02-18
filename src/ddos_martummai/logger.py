import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler, WatchedFileHandler
from typing import Union

from rich.logging import RichHandler


class AlignmentFilter(logging.Filter):
    def __init__(self, log_level_width=8, msg_level_width=14):
        super().__init__()
        self.log_level_width = log_level_width
        self.msg_level_width = msg_level_width

    def filter(self, record):
        level_colors = {
            "DEBUG": "dim cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "bold red",
            "CRITICAL": "bold white on red",
        }
        color = level_colors.get(record.levelname, "white")

        record.aligned_level = (
            f"[{color}]{record.levelname:<{self.log_level_width}}[/{color}]"
        )
        name_label = f"[{record.name}]"
        record.aligned_source = f"[cyan]{name_label:<{self.msg_level_width}}[/cyan]"

        return True


def get_console_logger(level=logging.INFO):
    root_logger = logging.getLogger()

    if root_logger.hasHandlers():
        return root_logger

    console_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_path=False,
        show_level=False,
        omit_repeated_times=False,
        log_time_format="[%Y-%m-%d %H:%M:%S]",
    )

    console_handler.addFilter(AlignmentFilter())
    fmt_str = "%(aligned_level)s %(aligned_source)s %(message)s"

    logging.basicConfig(
        level=level,
        format=fmt_str,
        datefmt=None,
        handlers=[console_handler],
    )
    return root_logger


def attach_file_logging(log_file_path: str, test_mode: bool = False):
    logger = logging.getLogger("LOGGER")
    try:
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

        is_prod_log = log_file_path.startswith("/var/log")

        if test_mode:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file_path = log_file_path.replace(".log", f"_test_{timestamp}.log")

        file_handler: Union[WatchedFileHandler, TimedRotatingFileHandler]

        if is_prod_log:
            file_handler = WatchedFileHandler(filename=log_file_path, encoding="utf-8")
        else:
            rotating_handler = TimedRotatingFileHandler(
                filename=log_file_path,
                when="midnight",
                interval=1,
                backupCount=30,
                encoding="utf-8",
            )
            rotating_handler.suffix = "%Y-%m-%d"
            file_handler = rotating_handler

        file_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)

        logging.getLogger().addHandler(file_handler)

        logger.info(f"File logging enabled at: {log_file_path}")

    except Exception as e:
        logger.error(f"Failed to setup file logging: {e}")
