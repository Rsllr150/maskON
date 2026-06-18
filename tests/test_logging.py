"""Tests for the structured JSON log formatter."""

import json
import logging

from maskon.api.logging_config import JsonFormatter


def test_formatter_emits_json_with_standard_fields():
    record = logging.LogRecord(
        name="maskon.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request",
        args=(),
        exc_info=None,
    )
    out = json.loads(JsonFormatter().format(record))
    assert out["level"] == "INFO"
    assert out["logger"] == "maskon.access"
    assert out["msg"] == "request"


def test_formatter_merges_extra_fields():
    record = logging.LogRecord(
        name="maskon.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request",
        args=(),
        exc_info=None,
    )
    record.request_id = "abc123"
    record.status = 200
    out = json.loads(JsonFormatter().format(record))
    assert out["request_id"] == "abc123"
    assert out["status"] == 200
