import copy
import logging
import os
from datetime import datetime
from logging.handlers import (
    QueueHandler,
    QueueListener,
    TimedRotatingFileHandler,
    WatchedFileHandler,
)
from multiprocessing import Queue
from typing import Any, Optional, Union

import uvicorn
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

        name = record.name
        if name.startswith("uvicorn"):
            name = "WEB"

        name_label = f"[{name}]"
        record.aligned_source = f"[cyan]{name_label:<{self.msg_level_width}}[/cyan]"

        record.plain_level = f"{record.levelname:<{self.log_level_width}}"
        record.plain_source = f"{name_label:<{self.msg_level_width}}"

        return True


def _create_file_handler(log_file_path: str, test_mode: bool):
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

        return file_handler
    except Exception as e:
        print(f"Failed to setup file logging: {e}")
        return None


def setup_worker_logger(log_queue: Queue, level=logging.INFO):
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers = []

    if log_queue:
        queue_handler = QueueHandler(log_queue)
        root_logger.addHandler(queue_handler)


def setup_main_logger(
    level=logging.INFO, log_file_path: Optional[str] = None, test_mode: bool = False
):
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers = []
    align_filter = AlignmentFilter()

    handlers = []

    # Console Handler
    console_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_path=False,
        show_level=False,
        omit_repeated_times=False,
        log_time_format="[%Y-%m-%d %H:%M:%S]",
    )
    console_handler.addFilter(align_filter)
    formatter = logging.Formatter("%(aligned_level)s %(aligned_source)s %(message)s")
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)

    # File Handler
    if log_file_path:
        file_handler = _create_file_handler(log_file_path, test_mode)
        if file_handler:
            file_handler.addFilter(align_filter)

            file_formatter = logging.Formatter(
                "%(asctime)s.%(msecs)03d | %(plain_level)s | %(plain_source)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_formatter)
            handlers.append(file_handler)

    for h in handlers:
        root_logger.addHandler(h)

    # Using Any for the Queue type hint since it acts as a pipe for serialized
    # LogRecord objects from multiple worker processes. Strict typing is avoided
    # here to remain compatible with various record formats sent by different modules.
    log_queue: Queue[Any] = Queue(-1)
    listener = QueueListener(log_queue, *handlers, respect_handler_level=True)

    return log_queue, listener


def setup_uvicorn_logging():
    log_config = copy.deepcopy(uvicorn.config.LOGGING_CONFIG)

    log_config["formatters"] = {}
    log_config["handlers"] = {}

    log_config["loggers"]["uvicorn"] = {"handlers": [], "propagate": True}
    log_config["loggers"]["uvicorn.error"] = {"level": "INFO", "propagate": True}
    log_config["loggers"]["uvicorn.access"] = {"level": "INFO", "propagate": True}

    return log_config
