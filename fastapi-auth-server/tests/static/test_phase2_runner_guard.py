import hashlib
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
RUNNER = ROOT / "ops" / "run-phase2-integration.sh"
EVIDENCE = ROOT / "evidence" / "phase2"


def _evidence_snapshot() -> dict[str, tuple[int, int, str]]:
    snapshot: dict[str, tuple[int, int, str]] = {}
    if not EVIDENCE.exists():
        return snapshot
    for path in sorted(item for item in EVIDENCE.rglob("*") if item.is_file()):
        stat = path.stat()
        snapshot[str(path.relative_to(EVIDENCE))] = (
            stat.st_mtime_ns,
            stat.st_size,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
    return snapshot


@pytest.mark.parametrize("variable", ["PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE"])
def test_phase2_runner_rejects_ambient_libpq_before_docker_or_evidence_mutation(
    tmp_path: Path,
    variable: str,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker_sentinel = tmp_path / "docker-invoked"
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        f"#!/bin/sh\nprintf invoked >'{docker_sentinel}'\nexit 99\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)

    blocked_prefixes = (
        "PG",
        "COMPOSE_",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "WISEACCT_FASTAPI_DEV_ENV_FILE",
        "AUTH_DB_",
        "DATABASE_URL",
        "REDIS_URL",
        "PORT",
    )
    clean_environment = {
        key: value
        for key, value in os.environ.items()
        if not any(key.startswith(prefix) for prefix in blocked_prefixes)
    }
    clean_environment["PATH"] = f"{fake_bin}:{os.environ['PATH']}"
    clean_environment[variable] = "must-not-be-used"
    evidence_before = _evidence_snapshot()

    result = subprocess.run(  # noqa: S603
        [str(RUNNER)],
        cwd=ROOT,
        env=clean_environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "libpq PG* overrides" in result.stderr
    assert not docker_sentinel.exists()
    assert _evidence_snapshot() == evidence_before


def test_phase2_host_postgres_tools_receive_only_explicit_minimal_environment() -> None:
    source = RUNNER.read_text(encoding="utf-8")

    assert source.count('env -i PATH="${PATH}" PGPASSWORD=') == 3
    assert all(not line.startswith("PGPASSWORD=") for line in source.splitlines())
