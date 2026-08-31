import os
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from wiseacct_sso.config import Settings
from wiseacct_sso.lifecycle import LifecycleHooks
from wiseacct_sso.main import RequestLogger, create_app

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
