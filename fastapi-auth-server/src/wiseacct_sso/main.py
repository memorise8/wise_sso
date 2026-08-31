import inspect
import json
import re
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request, Response
from sqlalchemy.engine import make_url

from wiseacct_sso import __version__
from wiseacct_sso.config import Settings, get_settings
from wiseacct_sso.infrastructure.redis import RedisOptions, RedisStateStore
from wiseacct_sso.lifecycle import LifecycleHooks, create_lifespan
from wiseacct_sso.logging import configure_logging
from wiseacct_sso.persistence.database import Database

ReadinessCheck = Callable[[], bool | Awaitable[bool]]
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_KNOWN_ROUTES = {"/healthz", "/readyz"}
_KNOWN_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}


class RequestLogger(Protocol):
    def info(self, event: str, **event_kw: object) -> object: ...

    def warning(self, event: str, **event_kw: object) -> object: ...


@dataclass
class _RuntimeResources:
    database: Database | None = None
    redis: RedisStateStore | None = None


def _new_database(url: str) -> Database:
    return Database(url)


def _new_redis_store(url: str) -> RedisStateStore:
    return RedisStateStore.from_options(RedisOptions(url=url))


def _report_runtime_dependency_failure(
    stage: Literal["database_create", "redis_create", "database_ping", "redis_start", "cleanup"],
    error: Exception,
    *,
    dependency: Literal["database", "redis"] | None = None,
) -> None:
    record = {
        "event": "runtime_dependency_failure",
        "stage": stage,
        "error_type": type(error).__name__[:64],
    }
    if dependency is not None:
        record["dependency"] = dependency
    try:
        sys.stderr.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception:
        return


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
    """Build the Uvicorn app with isolated PostgreSQL and Redis ownership."""

    settings = get_settings()
    database_url = _async_postgres_url(settings.database_url)
    resources = _RuntimeResources()
    application: FastAPI

    async def close_resources(*, report_failure: bool) -> None:
        first_error: Exception | None = None
        if resources.redis is not None:
            try:
                await resources.redis.close()
            except Exception as error:
                _report_runtime_dependency_failure("cleanup", error, dependency="redis")
                first_error = error
        if resources.database is not None:
            try:
                await resources.database.close()
            except Exception as error:
                _report_runtime_dependency_failure("cleanup", error, dependency="database")
                if first_error is None:
                    first_error = error
        resources.redis = None
        resources.database = None
        application.state.redis_store = None
        application.state.database = None
        if report_failure and first_error is not None:
            raise RuntimeError("Runtime dependency shutdown failed") from None

    async def startup() -> None:
        stage: Literal[
            "database_create", "redis_create", "database_ping", "redis_start", "cleanup"
        ] = "database_create"
        try:
            resources.database = _new_database(database_url)
            stage = "redis_create"
            resources.redis = _new_redis_store(settings.redis_url)
            application.state.database = resources.database
            application.state.redis_store = resources.redis
            stage = "database_ping"
            await resources.database.ping()
            stage = "redis_start"
            await resources.redis.start()
        except Exception as error:
            _report_runtime_dependency_failure(stage, error)
            await close_resources(report_failure=False)
            raise RuntimeError("Runtime dependency startup failed") from None

    async def shutdown() -> None:
        await close_resources(report_failure=True)

    async def database_ready() -> bool:
        if resources.database is None:
            return False
        await resources.database.ping()
        return True

    application = create_app(
        settings=settings,
        readiness_check=database_ready,
        lifecycle_hooks=LifecycleHooks(startup=startup, shutdown=shutdown),
    )
    application.state.database = None
    application.state.redis_store = None
    return application


def _async_postgres_url(value: str) -> str:
    """Select asyncpg without interpolating or reporting credential-bearing URLs."""

    try:
        url = make_url(value)
    except Exception:
        raise ValueError("DATABASE_URL must be a valid PostgreSQL URL") from None
    if url.drivername in {"postgres", "postgresql"}:
        url = url.set(drivername="postgresql+asyncpg")
    elif url.drivername != "postgresql+asyncpg":
        raise ValueError("DATABASE_URL must use PostgreSQL") from None
    return url.render_as_string(hide_password=False)
