import os
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

import wiseacct_sso.main as main_module
from wiseacct_sso.config import Settings
from wiseacct_sso.infrastructure.redis import RedisUnavailableError
from wiseacct_sso.lifecycle import LifecycleHooks
from wiseacct_sso.main import RequestLogger, _async_postgres_url, create_app

ROOT = Path(__file__).parents[2]


@asynccontextmanager
async def running_client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield client


class RaisingLogger:
    def info(self, event: str, **event_kw: object) -> object:
        raise RuntimeError("telemetry unavailable")

    def warning(self, event: str, **event_kw: object) -> object:
        raise RuntimeError("telemetry unavailable")


class RecordingLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def info(self, event: str, **event_kw: object) -> object:
        self.events.append((event, event_kw))
        return None

    def warning(self, event: str, **event_kw: object) -> object:
        self.events.append((event, event_kw))
        return None


class FakeDatabase:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.available = True
        self.ping_calls = 0
        self.close_error: Exception | None = None

    async def ping(self) -> None:
        self.ping_calls += 1
        self.events.append("database.ping")
        if not self.available:
            raise ConnectionError("database unavailable")

    async def close(self) -> None:
        self.events.append("database.close")
        if self.close_error is not None:
            raise self.close_error


class FakeRedisStore:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.start_error: Exception | None = None
        self.close_error: Exception | None = None
        self.available = True

    async def start(self) -> None:
        self.events.append("redis.start")
        if self.start_error is not None:
            raise self.start_error

    async def close(self) -> None:
        self.events.append("redis.close")
        if self.close_error is not None:
            raise self.close_error

    async def get_raw(self, _key: bytes) -> bytes | None:
        self.events.append("redis.get_raw")
        if not self.available:
            raise RedisUnavailableError("get_raw")
        return b"value"


class FakeOAuthClient:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.close_error: Exception | None = None

    async def close(self) -> None:
        self.events.append("oauth.close")
        if self.close_error is not None:
            raise self.close_error


def runtime_app_with(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    database: FakeDatabase,
    redis: FakeRedisStore,
) -> FastAPI:
    monkeypatch.setattr(main_module, "get_settings", lambda: settings)
    monkeypatch.setattr(main_module, "_new_database", lambda _url: database)
    monkeypatch.setattr(main_module, "_new_redis_store", lambda _url: redis)
    monkeypatch.setattr(main_module, "_new_oauth_client", lambda: FakeOAuthClient(database.events))
    return main_module.create_runtime_app()


@pytest.mark.anyio
async def test_health_and_injectable_readiness_contract(synthetic_settings: Settings) -> None:
    app = create_app(settings=synthetic_settings, readiness_check=lambda: True)

    async with running_client(app) as client:
        health = await client.get("/healthz", headers={"x-request-id": "phase1-test"})
        ready = await client.get("/readyz")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert health.headers["x-request-id"] == "phase1-test"
    assert ready.status_code == 200
    assert ready.json() == {"status": "ok"}
    assert app.state.settings is synthetic_settings


@pytest.mark.anyio
async def test_readiness_failure_is_generic(synthetic_settings: Settings) -> None:
    async def unavailable() -> bool:
        return False

    app = create_app(settings=synthetic_settings, readiness_check=unavailable)
    async with running_client(app) as client:
        response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


@pytest.mark.anyio
async def test_readiness_exception_is_generic_but_logged(synthetic_settings: Settings) -> None:
    def broken_check() -> bool:
        raise RuntimeError("database details must not escape")

    logger = RecordingLogger()
    app = create_app(
        settings=synthetic_settings,
        readiness_check=broken_check,
        request_logger=logger,
    )
    async with running_client(app) as client:
        response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert "database" not in response.text
    assert ("readiness_check_failed", {"error_type": "RuntimeError"}) in logger.events


@pytest.mark.anyio
async def test_logging_failure_cannot_change_response(synthetic_settings: Settings) -> None:
    logger: RequestLogger = RaisingLogger()
    app = create_app(settings=synthetic_settings, request_logger=logger)
    async with running_client(app) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert app.state.telemetry_drop_count == 1


@pytest.mark.anyio
async def test_logging_failure_emits_bounded_sanitized_evidence(
    synthetic_settings: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    logger: RequestLogger = RaisingLogger()
    app = create_app(settings=synthetic_settings, request_logger=logger)
    async with running_client(app) as client:
        response = await client.get("/healthz")

    evidence = capsys.readouterr().err
    assert response.status_code == 200
    assert '"event":"telemetry_delivery_failed"' in evidence
    assert '"failed_event":"http_request_observed"' in evidence
    assert '"error_type":"RuntimeError"' in evidence
    assert "telemetry unavailable" not in evidence


@pytest.mark.anyio
async def test_lifespan_runs_startup_and_graceful_shutdown_hooks(
    synthetic_settings: Settings,
) -> None:
    events: list[str] = []

    async def startup() -> None:
        events.append("startup")

    async def shutdown() -> None:
        events.append("shutdown")

    app = create_app(
        settings=synthetic_settings,
        lifecycle_hooks=LifecycleHooks(startup=startup, shutdown=shutdown),
    )
    async with running_client(app):
        assert app.state.accepting_requests is True
        assert events == ["startup"]

    assert app.state.accepting_requests is False
    assert events == ["startup", "shutdown"]


@pytest.mark.anyio
async def test_runtime_startup_failure_cleans_partial_resources_without_details(
    synthetic_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    events: list[str] = []
    database = FakeDatabase(events)
    redis = FakeRedisStore(events)
    redis.start_error = ConnectionError("redis://credential@private-host")
    redis.close_error = RuntimeError("redis://cleanup-secret@private-host")
    app = runtime_app_with(monkeypatch, synthetic_settings, database, redis)

    with pytest.raises(RuntimeError, match=r"^Runtime dependency startup failed$") as failure:
        async with app.router.lifespan_context(app):
            pass

    assert "credential" not in str(failure.value)
    assert events == [
        "database.ping",
        "redis.start",
        "oauth.close",
        "redis.close",
        "database.close",
    ]
    assert app.state.accepting_requests is False
    assert app.state.database is None
    assert app.state.redis_store is None
    evidence = capsys.readouterr().err
    assert '"stage":"redis_start"' in evidence
    assert '"error_type":"ConnectionError"' in evidence
    assert '"stage":"cleanup"' in evidence
    assert '"dependency":"redis"' in evidence
    assert '"error_type":"RuntimeError"' in evidence
    assert "credential" not in evidence
    assert "cleanup-secret" not in evidence
    assert "private-host" not in evidence


@pytest.mark.anyio
async def test_database_startup_failure_reports_only_stage_and_type(
    synthetic_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    events: list[str] = []
    database = FakeDatabase(events)
    database.available = False
    app = runtime_app_with(
        monkeypatch,
        synthetic_settings,
        database,
        FakeRedisStore(events),
    )

    with pytest.raises(RuntimeError, match=r"^Runtime dependency startup failed$"):
        async with app.router.lifespan_context(app):
            pass

    evidence = capsys.readouterr().err
    assert '"stage":"database_ping"' in evidence
    assert '"error_type":"ConnectionError"' in evidence
    assert "database unavailable" not in evidence


@pytest.mark.anyio
async def test_runtime_readiness_tracks_database_outage_and_recovery_only(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    database = FakeDatabase(events)
    redis = FakeRedisStore(events)
    app = runtime_app_with(monkeypatch, synthetic_settings, database, redis)

    async with running_client(app) as client:
        assert (await client.get("/readyz")).status_code == 200
        database.available = False
        unavailable = await client.get("/readyz")
        database.available = True
        recovered = await client.get("/readyz")

    assert unavailable.status_code == 503
    assert unavailable.json() == {"status": "unavailable"}
    assert recovered.status_code == 200
    assert recovered.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_redis_post_start_outage_fails_operations_closed_but_not_readiness(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    database = FakeDatabase(events)
    redis = FakeRedisStore(events)
    app = runtime_app_with(monkeypatch, synthetic_settings, database, redis)

    async with running_client(app) as client:
        redis.available = False
        with pytest.raises(RedisUnavailableError):
            await app.state.redis_store.get_raw(b"auth-state")
        ready = await client.get("/readyz")

    assert ready.status_code == 200
    assert ready.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_runtime_shutdown_closes_oauth_redis_and_database_in_order(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    app = runtime_app_with(
        monkeypatch,
        synthetic_settings,
        FakeDatabase(events),
        FakeRedisStore(events),
    )

    async with running_client(app):
        pass

    assert events[-3:] == ["oauth.close", "redis.close", "database.close"]


@pytest.mark.anyio
async def test_runtime_rebinds_a_fresh_oauth_client_for_each_lifespan(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    created_clients: list[FakeOAuthClient] = []
    monkeypatch.setattr(main_module, "get_settings", lambda: synthetic_settings)
    monkeypatch.setattr(main_module, "_new_database", lambda _url: FakeDatabase(events))
    monkeypatch.setattr(main_module, "_new_redis_store", lambda _url: FakeRedisStore(events))

    def new_oauth_client() -> FakeOAuthClient:
        client = FakeOAuthClient(events)
        created_clients.append(client)
        return client

    monkeypatch.setattr(main_module, "_new_oauth_client", new_oauth_client)
    app = main_module.create_runtime_app()

    async with running_client(app):
        assert len(created_clients) == 1
        assert vars(app.state.phase4_services)["_oauth_client"] is created_clients[0]
        assert (
            vars(app.state.phase4_services)["_tokens"] is vars(app.state.phase6_services)["_tokens"]
        )
    assert app.state.phase4_services is None
    assert app.state.phase6_services is None
    async with running_client(app):
        assert len(created_clients) == 2
        assert vars(app.state.phase4_services)["_oauth_client"] is created_clients[1]
        assert (
            vars(app.state.phase4_services)["_tokens"] is vars(app.state.phase6_services)["_tokens"]
        )
    assert app.state.phase4_services is None
    assert app.state.phase6_services is None

    assert len(created_clients) == 2
    assert created_clients[0] is not created_clients[1]
    assert events.count("oauth.close") == 2


@pytest.mark.anyio
async def test_runtime_mounts_admin_router_under_both_express_prefixes(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    app = runtime_app_with(
        monkeypatch,
        synthetic_settings,
        FakeDatabase(events),
        FakeRedisStore(events),
    )
    async with running_client(app) as client:
        responses = [
            await client.get("/admin/users"),
            await client.get("/admin/audit-logs"),
            await client.get("/manage-api/users"),
            await client.get("/manage-api/audit-logs"),
        ]

    assert [response.status_code for response in responses] == [401, 401, 401, 401]
    assert all(response.json()["error"]["code"] == "UNAUTHORIZED" for response in responses)


@pytest.mark.anyio
async def test_runtime_cleanup_failure_is_sanitized_and_does_not_skip_database(
    synthetic_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    events: list[str] = []
    database = FakeDatabase(events)
    redis = FakeRedisStore(events)
    redis.close_error = ConnectionError("redis://secret@cleanup-host")
    app = runtime_app_with(monkeypatch, synthetic_settings, database, redis)

    with pytest.raises(RuntimeError, match=r"^Runtime dependency shutdown failed$"):
        async with running_client(app):
            pass

    assert events[-3:] == ["oauth.close", "redis.close", "database.close"]
    evidence = capsys.readouterr().err
    assert '"stage":"cleanup"' in evidence
    assert '"dependency":"redis"' in evidence
    assert '"error_type":"ConnectionError"' in evidence
    assert "secret" not in evidence
    assert "cleanup-host" not in evidence


def test_runtime_normalizes_only_postgresql_urls_without_leaking_password() -> None:
    normalized = _async_postgres_url("postgres://user:p%40ss@db.internal:5432/sso")

    assert normalized == "postgresql+asyncpg://user:p%40ss@db.internal:5432/sso"
    with pytest.raises(ValueError, match="must use PostgreSQL") as failure:
        _async_postgres_url("mysql://user:do-not-report@db.internal/sso")
    assert "do-not-report" not in str(failure.value)


def test_runtime_factory_fails_fast_without_required_environment() -> None:
    environment = {"PATH": os.environ["PATH"], "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from wiseacct_sso.main import create_runtime_app; create_runtime_app()",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode != 0
    assert "DATABASE_URL" in result.stderr
