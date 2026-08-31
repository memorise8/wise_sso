import inspect
import json
import re
import sys
import time
from collections.abc import Awaitable, Callable
from typing import Literal, Protocol
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request, Response

from wiseacct_sso import __version__
from wiseacct_sso.config import Settings, get_settings
from wiseacct_sso.lifecycle import LifecycleHooks, create_lifespan
from wiseacct_sso.logging import configure_logging

ReadinessCheck = Callable[[], bool | Awaitable[bool]]
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_KNOWN_ROUTES = {"/healthz", "/readyz"}
_KNOWN_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}


class RequestLogger(Protocol):
    def info(self, event: str, **event_kw: object) -> object: ...

    def warning(self, event: str, **event_kw: object) -> object: ...


async def _not_ready() -> bool:
    return False


def _request_id(value: str | None) -> str:
    return value if value is not None and _REQUEST_ID.fullmatch(value) else str(uuid4())


def _route(path: str) -> str:
    return path if path in _KNOWN_ROUTES else "unmatched"


def _outcome(status_code: int) -> Literal["1xx", "2xx", "3xx", "4xx", "5xx"]:
    return f"{min(max(status_code // 100, 1), 5)}xx"  # type: ignore[return-value]


def _safe_log(
    logger: RequestLogger,
    log_method: Literal["info", "warning"],
    event: str,
    on_failure: Callable[[], None],
    **values: object,
) -> None:
    try:
        getattr(logger, log_method)(event, **values)
    except Exception as error:
        on_failure()
        record = {
            "event": "telemetry_delivery_failed",
            "failed_event": event[:64],
            "error_type": type(error).__name__[:64],
        }
        try:
            sys.stderr.write(json.dumps(record, separators=(",", ":")) + "\n")
        except Exception:
            # The in-memory counter remains independently observable even if stderr is unavailable.
            return


def create_app(
    *,
    settings: Settings,
    readiness_check: ReadinessCheck = _not_ready,
    lifecycle_hooks: LifecycleHooks | None = None,
    request_logger: RequestLogger | None = None,
) -> FastAPI:
    configure_logging()
    application = FastAPI(
        title="WiseAcct SSO FastAPI PROVISIONAL",
        version=__version__,
        lifespan=create_lifespan(lifecycle_hooks or LifecycleHooks()),
    )
    application.state.settings = settings
    application.state.telemetry_drop_count = 0
    logger: RequestLogger = request_logger or structlog.get_logger()

    def record_telemetry_drop() -> None:
        application.state.telemetry_drop_count += 1

    @application.middleware("http")
    async def observe_request(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        started_at = time.perf_counter()
        request_id = _request_id(request.headers.get("x-request-id"))
        request.state.request_id = request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["x-request-id"] = request_id
            return response
        finally:
            method = request.method.upper()
            _safe_log(
                logger,
                "info",
                "http_request_observed",
                record_telemetry_drop,
                metric="sso_http_request",
                backend="fastapi",
                version=__version__,
                method=method if method in _KNOWN_METHODS else "OTHER",
                route=_route(request.url.path),
                outcome=_outcome(status_code),
                latency_ms=max(0.0, (time.perf_counter() - started_at) * 1000),
            )
            structlog.contextvars.clear_contextvars()

    @application.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/readyz")
    async def readyz(response: Response) -> dict[str, str]:
        try:
            result = readiness_check()
            is_ready = await result if inspect.isawaitable(result) else result
        except Exception as error:
            is_ready = False
            _safe_log(
                logger,
                "warning",
                "readiness_check_failed",
                record_telemetry_drop,
                error_type=type(error).__name__,
            )
        if not is_ready:
            response.status_code = 503
            return {"status": "unavailable"}
        return {"status": "ok"}

    return application


def create_runtime_app() -> FastAPI:
    """Uvicorn factory that fails before startup when environment validation fails."""

    return create_app(settings=get_settings())
