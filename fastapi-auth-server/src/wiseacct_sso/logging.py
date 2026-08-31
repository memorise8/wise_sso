import logging
from collections.abc import Mapping, MutableMapping, Sequence
from typing import Any

import structlog

_REDACTED = "[REDACTED]"
_TRUNCATED = "[TRUNCATED]"
_MAX_REDACTION_DEPTH = 6
_MAX_COLLECTION_ITEMS = 64
_SENSITIVE_FRAGMENTS = (
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
)
_ALLOWED_METRIC_KEYS = {
    "backend",
    "event",
    "latencyMs",
    "level",
    "method",
    "metric",
    "outcome",
    "route",
    "timestamp",
    "version",
}


def _redact_value(value: Any, depth: int) -> Any:
    if depth >= _MAX_REDACTION_DEPTH:
        return _TRUNCATED
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for index, (key, nested_value) in enumerate(value.items()):
            if index >= _MAX_COLLECTION_ITEMS:
                redacted["truncated"] = _TRUNCATED
                break
            text_key = str(key)
            if any(fragment in text_key.lower() for fragment in _SENSITIVE_FRAGMENTS):
                redacted[text_key] = _REDACTED
            else:
                redacted[text_key] = _redact_value(nested_value, depth + 1)
        return redacted
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = [_redact_value(item, depth + 1) for item in value[:_MAX_COLLECTION_ITEMS]]
        if len(value) > _MAX_COLLECTION_ITEMS:
            items.append(_TRUNCATED)
        return items
    return value


def redact_event_dict(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for key in tuple(event_dict):
        if any(fragment in key.lower() for fragment in _SENSITIVE_FRAGMENTS):
            event_dict[key] = _REDACTED
        else:
            event_dict[key] = _redact_value(event_dict[key], 0)
    return event_dict


def allowlist_request_metric(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    if event_dict.get("metric") != "sso_http_request":
        return event_dict
    return {key: value for key, value in event_dict.items() if key in _ALLOWED_METRIC_KEYS}


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            redact_event_dict,
            allowlist_request_metric,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
