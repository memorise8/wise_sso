import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
RUNNER = ROOT / "ops" / "run-phase7-qualification.sh"
VALIDATOR = ROOT / "ops" / "phase7" / "validate_inputs.py"
CONTRACT_GATE = ROOT / "ops" / "phase7" / "run-contract-gate.sh"
PLACEHOLDER_GATE = ROOT / "ops" / "phase7" / "run-placeholder-gate.sh"
PLACEHOLDER_CHECK = ROOT / "ops" / "phase7" / "check-placeholder-result.sh"


def validate(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed local validator and argument vector
        [sys.executable, str(VALIDATOR), *arguments],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        capture_output=True,
        text=True,
    )


def safe_arguments() -> list[str]:
    return [
        "--baseline",
        "http://127.0.0.1:4100",
        "--candidate",
        "http://localhost:4101",
        "--database",
        "postgresql+asyncpg://phase7:synthetic@127.0.0.1:5433/phase7_test_run",
        "--node-database",
        "postgresql://phase7:synthetic@127.0.0.1:5433/phase7_test_run",
        "--redis",
        "redis://127.0.0.1:6380/14",
    ]


def test_phase7_validator_accepts_only_sanitized_topology_output() -> None:
    result = validate(*safe_arguments())

    assert result.returncode == 0, result.stderr
    topology = json.loads(result.stdout)
    assert topology["database"]["database"] == "phase7_test_run"
    assert topology["redis"]["database"] == 14
    assert "synthetic" not in result.stdout


@pytest.mark.parametrize(
    ("option", "unsafe", "message"),
    [
        ("--baseline", "https://sso.example.com:443", "loopback only"),
        (
            "--database",
            "postgresql+asyncpg://user:secret@127.0.0.1:5433/production",
            "distinct 'test' segment",
        ),
        ("--redis", "redis://127.0.0.1:6380/0", "isolated database"),
        ("--redis", "redis://127.0.0.1:6379/14", "default Redis port"),
    ],
)
def test_phase7_validator_rejects_nonisolated_targets_without_echoing_credentials(
    option: str,
    unsafe: str,
    message: str,
) -> None:
    arguments = safe_arguments()
    arguments[arguments.index(option) + 1] = unsafe

    result = validate(*arguments)

    assert result.returncode == 2
    assert message in result.stderr
    assert "secret" not in result.stderr


@pytest.mark.parametrize(
    "node_database",
    [
        "postgresql://phase7:synthetic@localhost:5433/phase7_test_run",
        "postgresql://phase7:synthetic@127.0.0.1:5544/phase7_test_run",
        "postgresql://phase7:synthetic@127.0.0.1:5433/other_test_run",
    ],
)
def test_phase7_validator_requires_the_exact_shared_database_endpoint(
    node_database: str,
) -> None:
    arguments = safe_arguments()
    arguments[arguments.index("--node-database") + 1] = node_database

    result = validate(*arguments)

    assert result.returncode == 2
    assert "same host, port, and test database" in result.stderr


def test_phase7_runner_is_clean_commit_first_and_fail_closed() -> None:
    source = RUNNER.read_text(encoding="utf-8")

    lock_guard = source.index("flock --nonblock 8")
    clean_guard = source.index("status --porcelain=v1 --untracked-files=all")
    input_guard = source.index("validate_inputs.py")
    evidence_creation = source.index('mkdir -p -- "${EVIDENCE_DIR}"')
    contract_gate = source.index("run-contract-gate.sh")
    placeholder_loop = source.index(
        "for gate in performance security chaos backup-restore local-rollback"
    )

    assert lock_guard < clean_guard < input_guard < evidence_creation < contract_gate
    assert contract_gate < placeholder_loop
    assert "provenance_is_stable" in source
    assert "passedGate=public-contract" in source
    assert "contractScope=public-only" in source
    assert "overallReplacementReady=false" in source
    assert "exit 3" in source
    assert "chmod -R a-w" in source


def test_phase7_runner_has_no_production_routing_or_service_mutation_commands() -> None:
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [RUNNER, *(ROOT / "ops" / "phase7").glob("*.sh")]
    )

    forbidden = (
        "docker compose",
        "docker-compose",
        "kubectl",
        "systemctl",
        "nginx",
        "DROP DATABASE",
        "FLUSHALL",
        "FLUSHDB",
    )
    assert all(command not in sources for command in forbidden)


def test_phase7_contract_gate_preserves_failure_status(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed local gate and loopback-only targets
        [
            str(CONTRACT_GATE),
            "http://127.0.0.1:9",
            "http://127.0.0.1:10",
            str(ROOT.parent / "contracts" / "scenarios" / "public.json"),
            str(tmp_path),
        ],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"]},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    contract_status = (tmp_path / "contract.status").read_text(encoding="utf-8")
    assert "gate=public-contract" in contract_status
    assert "scope=public-only" in contract_status
    assert "fixtures=NOT_RUN" in contract_status
    assert "guards=NOT_RUN" in contract_status
    assert "status=FAIL" in contract_status
    records = [
        json.loads(line)
        for line in (tmp_path / "public-contract-results.jsonl").read_text().splitlines()
    ]
    assert records
    assert all(record["provenance"]["topology"] == "public-only" for record in records)
    assert all(
        set(record["provenance"]) == {"runId", "scenarioHash", "sourceRevision", "topology"}
        for record in records
    )


def test_phase7_placeholder_is_an_explicit_incomplete_gate(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed local placeholder gate
        [str(PLACEHOLDER_GATE), "security", str(tmp_path)],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"]},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 3
    status = (tmp_path / "security.status").read_text(encoding="utf-8")
    assert "status=SKIP" in status
    assert "reason=not-implemented" in status

    accepted = subprocess.run(  # noqa: S603 - fixed local checker
        [str(PLACEHOLDER_CHECK), "security", str(tmp_path), "3"],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"]},
        check=False,
    )
    assert accepted.returncode == 0


@pytest.mark.parametrize(("exit_code", "expected"), [("7", 7), ("0", 1), ("3", 3)])
def test_phase7_placeholder_checker_propagates_unexpected_results(
    tmp_path: Path,
    exit_code: str,
    expected: int,
) -> None:
    (tmp_path / "chaos.status").write_text(
        "gate=chaos\nstatus=FAIL\nreason=unexpected\n",
        encoding="utf-8",
    )

    result = subprocess.run(  # noqa: S603 - fixed local checker
        [str(PLACEHOLDER_CHECK), "chaos", str(tmp_path), exit_code],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"]},
        check=False,
    )

    assert result.returncode == expected
