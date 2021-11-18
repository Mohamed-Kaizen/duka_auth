"""Custom Logger for Duka auth project."""
import logging
from pprint import pformat
from typing import Any, Dict

from loguru import logger
from loguru._defaults import LOGURU_FORMAT


class InterceptHandler(logging.Handler):
    """Default handler from examples in loguru documentation."""

    def emit(self: "InterceptHandler", record: logging.LogRecord) -> None:
        """Do whatever it takes to actually log the specified logging record."""
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.name

        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back  # type: ignore
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def log_format(payload: Dict[str, Any]) -> str:
    """Custom format for loguru loggers.

    Uses pformat for log any data like request/response body during debug.
    Works with logging if loguru handler it.

    Args:
        payload: Dict of custom payload to add it to the logger

    Returns:
        A formated string for logger.

    Example:
    >>> custom_payload = {"extra": {"payload": {"ip":"192.168.1.0"}}}
    >>> type(log_format(payload=custom_payload)) == str
    True
    """
    format_string = LOGURU_FORMAT

    if payload["extra"].get("payload") is not None:
        payload["extra"]["payload"] = pformat(
            payload["extra"]["payload"], indent=4, compact=True, width=88
        )
        format_string += "\n<level>{extra[payload]}</level>"

    format_string += "{exception}\n"
    return format_string
