import json
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import structlog
from fastapi import FastAPI
from sqlalchemy.engine import make_url

from wiseacct_sso import __version__
from wiseacct_sso.api.errors import ExpressJsonResponse, install_error_handlers
from wiseacct_sso.api.middleware import (
    ExpressCorsMiddleware,
    GenericErrorMiddleware,
    KnownPathCompatibilityMiddleware,
    RequestInstrumentationMiddleware,
    SecurityHeadersMiddleware,
    safe_log,
)
from wiseacct_sso.api.middleware import (
    RequestLogger as RequestLogger,
)
from wiseacct_sso.api.routes.system import build_system_router
from wiseacct_sso.api.staticfiles import ImmutableStaticFiles
from wiseacct_sso.config import Settings, get_settings
from wiseacct_sso.infrastructure.redis import RedisOptions, RedisStateStore
from wiseacct_sso.lifecycle import LifecycleHooks, create_lifespan
from wiseacct_sso.logging import configure_logging
from wiseacct_sso.persistence.database import Database

ReadinessCheck = Callable[[], bool | Awaitable[bool]]
_STATIC_ROOT = Path(__file__).with_name("static")


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
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
        default_response_class=ExpressJsonResponse,
    )
    application.state.settings = settings
    application.state.telemetry_drop_count = 0
    logger: RequestLogger = request_logger or structlog.get_logger()

    def record_telemetry_drop() -> None:
        application.state.telemetry_drop_count += 1

    def report_readiness_error(error: Exception) -> None:
        safe_log(
            logger,
            "warning",
            "readiness_check_failed",
            record_telemetry_drop,
            error_type=type(error).__name__,
        )

    install_error_handlers(application)
    application.include_router(
        build_system_router(
            settings=settings,
            readiness_check=readiness_check,
            static_root=_STATIC_ROOT,
            on_readiness_error=report_readiness_error,
        )
    )
    application.mount(
        "/assets",
        ImmutableStaticFiles(directory=_STATIC_ROOT / "assets"),
        name="assets",
    )

    # Starlette inserts each middleware at the front. Add from innermost to outermost
    # to preserve instrumentation → security → CORS → errors → path compatibility.
    application.add_middleware(KnownPathCompatibilityMiddleware)
    application.add_middleware(GenericErrorMiddleware)
    application.add_middleware(ExpressCorsMiddleware, allowed_origins=settings.cors_allowed_origins)
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(
        RequestInstrumentationMiddleware,
        logger=logger,
        on_delivery_failure=record_telemetry_drop,
    )
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
