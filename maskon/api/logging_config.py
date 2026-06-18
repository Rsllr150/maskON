"""Structured JSON logging.

Scoped to the "maskon" logger (not the root) so it never clobbers the test
runner's log capture. Each record is emitted as a single JSON line; fields
passed via ``extra={...}`` are merged in.
"""

import json
import logging
from typing import Any

# Standard LogRecord attributes — used to tell apart user-supplied extras.
_RESERVED = set(vars(logging.makeLogRecord({})))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                data[key] = value
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False)


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("maskon")
    logger.handlers = [handler]
    logger.setLevel(level)
    logger.propagate = False
