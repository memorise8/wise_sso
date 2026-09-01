from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT.parent
PHASE7 = ROOT / "ops" / "phase7"
MATERIAL = PHASE7 / "runtime_shared_material.py"
VALIDATOR = PHASE7 / "validate_shared_inputs.py"
GATE = PHASE7 / "run-shared-state-core-gate.sh"
LAUNCHER = ROOT / "ops" / "run-phase7-shared-integration.sh"
README = PHASE7 / "README.md"


def run_material(tmp_path: Path) -> dict[str, dict[str, str]]:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    subprocess.run(  # noqa: S603 - fixed repository helper path
        [
            str(MATERIAL),
            "--example",
            str(ROOT / ".env.example"),
            "--private-dir",
            str(private),
            "--run-id",
            "shared_test_123",
            "--express-port",
            "4410",
            "--fastapi-port",
            "4411",
        ],
        check=True,
    )
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8")) for path in private.glob("*.json")
    }


def test_material_uses_one_database_two_roles_and_one_redis(tmp_path: Path) -> None:
    documents = run_material(tmp_path)
    express = urlsplit(documents["express-adapter"]["CONTRACT_DATABASE_URL"])
    fastapi = urlsplit(documents["fastapi-adapter"]["CONTRACT_DATABASE_URL"])
    assert (express.hostname, express.port, express.path) == (
        fastapi.hostname,
        fastapi.port,
        fastapi.path,
    )
    assert express.username != fastapi.username
    assert express.password != fastapi.password
    assert (
        documents["express-adapter"]["CONTRACT_REDIS_URL"]
        == (documents["fastapi-adapter"]["CONTRACT_REDIS_URL"])
    )
    assert documents["express-adapter"]["CONTRACT_REDIS_URL"].endswith("/13")


def test_material_shares_security_and_client_policy(tmp_path: Path) -> None:
    documents = run_material(tmp_path)
    express = documents["express-runtime"]
    fastapi = documents["fastapi-runtime"]
    for key in (
        "JWT_ACCESS_ALGORITHM",
        "JWT_ACCESS_PRIVATE_KEY",
        "JWT_ACCESS_PUBLIC_JWK",
        "JWT_REFRESH_SECRET",
        "JWT_ISSUER",
        "JWT_AUDIENCE",
        "AUTH_CLIENTS_JSON",
    ):
        assert express[key] == fastapi[key]
    assert express["OAUTH_ENABLED_PROVIDERS"] == fastapi["OAUTH_ENABLED_PROVIDERS"] == ""
    assert express["MAIL_PROVIDER"] == fastapi["MAIL_PROVIDER"] == "dev"


def test_material_files_are_private(tmp_path: Path) -> None:
    run_material(tmp_path)
    for path in (tmp_path / "private").iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def validator_inputs(tmp_path: Path) -> tuple[list[str], dict[str, str]]:
    documents = run_material(tmp_path)
    private = tmp_path / "private"
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir(mode=0o700)
    express_db = documents["express-adapter"]["CONTRACT_DATABASE_URL"]
    fastapi_node_db = documents["fastapi-adapter"]["CONTRACT_DATABASE_URL"]
    fastapi_db = fastapi_node_db.replace("postgresql://", "postgresql+asyncpg://", 1)
    redis = documents["express-adapter"]["CONTRACT_REDIS_URL"]
    command = [
        str(VALIDATOR),
        "--express",
        "http://127.0.0.1:4410",
        "--fastapi",
        "http://127.0.0.1:4411",
        "--express-config",
        str(private / "express-adapter.json"),
        "--fastapi-config",
        str(private / "fastapi-adapter.json"),
        "--snapshot-dir",
        str(snapshot),
        "--repo",
        str(REPO),
        "--evidence",
        str(ROOT / "evidence"),
    ]
    environment = {
        **os.environ,
        "WISEACCT_PHASE7_EXPRESS_DATABASE_URL": express_db,
        "WISEACCT_PHASE7_FASTAPI_DATABASE_URL": fastapi_db,
        "WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL": fastapi_node_db,
        "WISEACCT_PHASE7_EXPRESS_REDIS_URL": redis,
        "WISEACCT_PHASE7_FASTAPI_REDIS_URL": redis,
    }
    return command, environment


def test_validator_accepts_exact_shared_topology(tmp_path: Path) -> None:
    command, environment = validator_inputs(tmp_path)
    completed = subprocess.run(  # noqa: S603 - command is assembled from fixed helper argv
        command, env=environment, check=False, capture_output=True, text=True
    )
    assert completed.returncode == 0, completed.stderr
    topology = json.loads(completed.stdout)
    assert topology["postgres"]["distinctRuntimeRoles"] is True
    assert topology["redis"]["shared"]["database"] == 13


def test_validator_rejects_separate_database(tmp_path: Path) -> None:
    command, environment = validator_inputs(tmp_path)
    environment["WISEACCT_PHASE7_FASTAPI_DATABASE_URL"] = environment[
        "WISEACCT_PHASE7_FASTAPI_DATABASE_URL"
    ].replace("phase7_shared_test", "phase7_other_test")
    completed = subprocess.run(  # noqa: S603 - command is assembled from fixed helper argv
        command, env=environment, check=False
    )
    assert completed.returncode == 2


def test_validator_rejects_separate_redis_or_wrong_db(tmp_path: Path) -> None:
    command, environment = validator_inputs(tmp_path)
    environment["WISEACCT_PHASE7_FASTAPI_REDIS_URL"] = (
        environment["WISEACCT_PHASE7_FASTAPI_REDIS_URL"].removesuffix("13") + "14"
    )
    completed = subprocess.run(  # noqa: S603 - command is assembled from fixed helper argv
        command, env=environment, check=False
    )
    assert completed.returncode == 2


def test_validator_rejects_same_runtime_role(tmp_path: Path) -> None:
    command, environment = validator_inputs(tmp_path)
    environment["WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL"] = environment[
        "WISEACCT_PHASE7_EXPRESS_DATABASE_URL"
    ]
    environment["WISEACCT_PHASE7_FASTAPI_DATABASE_URL"] = environment[
        "WISEACCT_PHASE7_EXPRESS_DATABASE_URL"
    ].replace("postgresql://", "postgresql+asyncpg://", 1)
    completed = subprocess.run(  # noqa: S603 - command is assembled from fixed helper argv
        command, env=environment, check=False
    )
    assert completed.returncode == 2


def test_validator_rejects_non_private_config(tmp_path: Path) -> None:
    command, environment = validator_inputs(tmp_path)
    Path(command[command.index("--express-config") + 1]).chmod(0o644)
    completed = subprocess.run(  # noqa: S603 - command is assembled from fixed helper argv
        command, env=environment, check=False
    )
    assert completed.returncode == 2


def test_gate_uses_agreed_black_box_runner_interface() -> None:
    source = GATE.read_text(encoding="utf-8")
    for option in (
        '--express "${EXPRESS_URL}"',
        '--fastapi "${FASTAPI_URL}"',
        '--scenarios "${SCENARIOS}"',
        '--fixture-adapter "${EXPRESS_ADAPTER}"',
        '--fixture-config "${PRIVATE_SNAPSHOTS}/express.json"',
        '--jsonl "${OUTPUT}"',
        '--run-id "${RUN_ID}"',
        '--source-revision "${SOURCE_REVISION}"',
    ):
        assert option in source


def test_gate_preflights_both_adapters_and_requires_exact_sample() -> None:
    source = GATE.read_text(encoding="utf-8")
    assert "run_adapter_preflights.py" in source
    assert '--express-adapter "${EXPRESS_ADAPTER}"' in source
    assert '--fastapi-adapter "${FASTAPI_ADAPTER}"' in source
    assert '[[ "${result_count}" != 100 ]]' in source
    assert "mismatchCount=0" in source
    assert "fullPhase7SampleSatisfied=false" in source
    assert "overallReplacementReady=false" in source


def test_launcher_creates_one_database_and_migrates_once() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    assert source.count("CREATE DATABASE") == 1
    assert source.count("npx prisma migrate deploy") == 1
    assert "P7_SHARED_DATABASE" in source
    assert "P7_EXPRESS_ROLE" in source and "P7_FASTAPI_ROLE" in source


def test_launcher_clears_only_redis_13() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    assert "--database 13" in source
    assert "--database 14" not in source
    assert "FLUSHALL" not in source
    assert "FLUSHDB" not in source


def test_launcher_preserves_production_and_reuses_fail_closed_guards() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    assert "snapshot_express" in source
    assert "runtime_candidate_state.py resources" in source
    assert source.count("runtime_listen_guard.py") == 2
    assert "flock --nonblock 8" in source
    assert "runtime_shared_publish.py" in source
    assert "runtime_private_remove.py" in source
    assert "docker restart" not in source
    assert "docker stop" not in source
    assert "if ! candidate_resources_state" not in source


def test_launcher_requires_clean_committed_tree_before_mutation() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    clean = source.index("status --porcelain=v1")
    compose = source.index('dev-compose.sh" up')
    assert clean < compose


def test_shared_gate_is_documented_as_incremental_only() -> None:
    source = README.read_text(encoding="utf-8")
    assert "shared-state-core-v1" in source
    assert "fullPhase7SampleSatisfied=false" in source
    assert "overallReplacementReady=false" in source
