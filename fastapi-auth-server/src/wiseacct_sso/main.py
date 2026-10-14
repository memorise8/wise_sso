import json
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import structlog
from fastapi import FastAPI
from sqlalchemy.engine import make_url
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from wiseacct_sso import __version__
from wiseacct_sso.api.dependencies import Phase4Services, Phase6Services
from wiseacct_sso.api.errors import ExpressJsonResponse, install_error_handlers
from wiseacct_sso.api.middleware import (
    AuthRateLimitMiddleware,
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
from wiseacct_sso.api.routes.admin import build_admin_router
from wiseacct_sso.api.routes.auth import build_auth_router
from wiseacct_sso.api.routes.oauth import build_oauth_router
from wiseacct_sso.api.routes.system import build_system_router
from wiseacct_sso.api.routes.users import build_users_router
from wiseacct_sso.api.staticfiles import ImmutableStaticFiles
from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.application.auth import Phase5AuthService
from wiseacct_sso.config import Settings, get_settings
from wiseacct_sso.domain.auth import PasswordPolicy
from wiseacct_sso.infrastructure.mail import create_mail_service
from wiseacct_sso.infrastructure.oauth_providers import OAuthProviderClient, provider_config_for
from wiseacct_sso.infrastructure.redis import RedisOptions, RedisStateStore
from wiseacct_sso.infrastructure.security import AsyncPasswordHasher, JwtTokenCodec
from wiseacct_sso.lifecycle import LifecycleHooks, create_lifespan
from wiseacct_sso.logging import configure_logging
from wiseacct_sso.persistence.database import Database

ReadinessCheck = Callable[[], bool | Awaitable[bool]]
_STATIC_ROOT = Path(__file__).with_name("static")


@dataclass
class _RuntimeResources:
    database: Database | None = None
    redis: RedisStateStore | None = None
    oauth_client: OAuthProviderClient | None = None


def _new_database(url: str) -> Database:
    return Database(url)


def _new_redis_store(url: str) -> RedisStateStore:
    return RedisStateStore.from_options(RedisOptions(url=url))


def _new_oauth_client() -> OAuthProviderClient:
    return OAuthProviderClient()


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
    phase4_services: Phase4Services | None = None,
    phase6_services: Phase6Services | None = None,
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
    application.state.phase4_services = phase4_services
    application.state.phase6_services = phase6_services
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
    if phase4_services is not None:
        application.include_router(build_auth_router())
        application.include_router(build_users_router())
        if hasattr(phase4_services, "oauth_start"):
            application.include_router(build_oauth_router())
    if phase6_services is not None:
        application.include_router(build_admin_router(prefix="/admin"))
        application.include_router(build_admin_router(prefix="/manage-api"))
    application.mount(
        "/assets",
        ImmutableStaticFiles(directory=_STATIC_ROOT / "assets"),
        name="assets",
    )

    # Starlette inserts each middleware at the front. Add from innermost to outermost
    # so validated proxy metadata is available before instrumentation and rate limiting.
    application.add_middleware(KnownPathCompatibilityMiddleware)
    if phase4_services is not None:
        application.add_middleware(AuthRateLimitMiddleware, services=phase4_services)
    application.add_middleware(GenericErrorMiddleware)
    application.add_middleware(ExpressCorsMiddleware, allowed_origins=settings.cors_allowed_origins)
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(
        RequestInstrumentationMiddleware,
        logger=logger,
        on_delivery_failure=record_telemetry_drop,
    )
    if settings.trusted_proxy_ips:
        application.add_middleware(
            ProxyHeadersMiddleware,
            trusted_hosts=list(settings.trusted_proxy_ips),
        )
    return application


def create_runtime_app() -> FastAPI:
    """Build the Uvicorn app with isolated PostgreSQL and Redis ownership."""

    settings = get_settings()
    database_url = _async_postgres_url(settings.database_url)
    resources = _RuntimeResources()
    application: FastAPI

    def runtime_database() -> Database:
        if resources.database is None:
            raise RuntimeError("Runtime database is unavailable")
        return resources.database

    def runtime_redis() -> RedisStateStore:
        if resources.redis is None:
            raise RuntimeError("Runtime Redis is unavailable")
        return resources.redis

    frontend_origin = _frontend_origin(settings.frontend_redirect_url)
    mail_service = create_mail_service(settings)
    token_codec = JwtTokenCodec.from_settings(settings)
    phase5_services = Phase5AuthService(
        database=runtime_database,
        redis=runtime_redis,
        passwords=AsyncPasswordHasher(),
        tokens=token_codec,
        password_policy=PasswordPolicy(
            min_length=settings.password_min_length,
            allowed_email_domain=settings.company_allowed_email_domain or None,
        ),
        default_audience=settings.jwt_audience,
        rate_limit_window_seconds=settings.auth_rate_limit_window_seconds,
        rate_limit_max_requests=settings.auth_rate_limit_max_requests,
        mail=mail_service,
        verification_url_base=f"{frontend_origin}/verify-email",
        password_reset_url_base=f"{frontend_origin}/password-reset",
        auth_clients=settings.auth_clients,
        provider_config=lambda provider: provider_config_for(settings, provider),
        oauth_client=None,
    )
    phase6_services = Phase6AdminService(database=runtime_database, tokens=token_codec)

    async def close_resources(*, report_failure: bool) -> None:
        first_error: Exception | None = None
        if resources.oauth_client is not None:
            oauth_client = resources.oauth_client
            try:
                await oauth_client.close()
            except Exception as error:
                _report_runtime_dependency_failure("cleanup", error)
                first_error = error
            finally:
                phase5_services.unbind_oauth_client(oauth_client)
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
        resources.oauth_client = None
        application.state.redis_store = None
        application.state.database = None
        application.state.phase4_services = None
        application.state.phase6_services = None
        if report_failure and first_error is not None:
            raise RuntimeError("Runtime dependency shutdown failed") from None

    async def startup() -> None:
        stage: Literal[
            "database_create", "redis_create", "database_ping", "redis_start", "cleanup"
        ] = "database_create"
        try:
            resources.oauth_client = _new_oauth_client()
            phase5_services.bind_oauth_client(resources.oauth_client)
            resources.database = _new_database(database_url)
            stage = "redis_create"
            resources.redis = _new_redis_store(settings.redis_url)
            application.state.database = resources.database
            application.state.redis_store = resources.redis
            stage = "database_ping"
            await resources.database.ping()
            stage = "redis_start"
            await resources.redis.start()
            application.state.phase4_services = phase5_services
            application.state.phase6_services = phase6_services
        except Exception as error:
            _report_runtime_dependency_failure(stage, error)
            await close_resources(report_failure=False)
            raise RuntimeError("Runtime dependency startup failed") from None

    async def shutdown() -> None:
        await close_resources(report_failure=True)

    async def runtime_ready() -> bool:
        if resources.database is None or resources.redis is None:
            return False
        await resources.database.ping()
        await resources.redis.ping()
        return True

    application = create_app(
        settings=settings,
        readiness_check=runtime_ready,
        lifecycle_hooks=LifecycleHooks(startup=startup, shutdown=shutdown),
        phase4_services=phase5_services,
        phase6_services=phase6_services,
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


def _frontend_origin(value: str) -> str:
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("FRONTEND_REDIRECT_URL must contain a hostname")
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if parsed.scheme == "https" else 80
    suffix = f":{parsed.port}" if parsed.port is not None and parsed.port != default_port else ""
    return f"{parsed.scheme}://{host}{suffix}"
