from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT.parent
PHASE7 = ROOT / "ops" / "phase7"
MATERIAL = PHASE7 / "runtime_shared_material.py"
VALIDATOR = PHASE7 / "validate_shared_inputs.py"
GATE = PHASE7 / "run-shared-state-core-gate.sh"
LAUNCHER = ROOT / "ops" / "run-phase7-shared-integration.sh"
README = PHASE7 / "README.md"
PUBLISHER = PHASE7 / "runtime_shared_publish.py"
RESULT_VALIDATOR = PHASE7 / "validate_shared_result.py"
PUBLISHER_SPEC = importlib.util.spec_from_file_location("phase7_shared_publish", PUBLISHER)
assert PUBLISHER_SPEC is not None and PUBLISHER_SPEC.loader is not None
publisher = importlib.util.module_from_spec(PUBLISHER_SPEC)
sys.modules[PUBLISHER_SPEC.name] = publisher
PUBLISHER_SPEC.loader.exec_module(publisher)
RESULT_SPEC = importlib.util.spec_from_file_location("phase7_shared_result", RESULT_VALIDATOR)
assert RESULT_SPEC is not None and RESULT_SPEC.loader is not None
result_validator = importlib.util.module_from_spec(RESULT_SPEC)
sys.modules[RESULT_SPEC.name] = result_validator
RESULT_SPEC.loader.exec_module(result_validator)


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


def test_validator_rejects_fastapi_python_runtime_credential_mismatch(tmp_path: Path) -> None:
    command, environment = validator_inputs(tmp_path)
    environment["WISEACCT_PHASE7_FASTAPI_DATABASE_URL"] = environment[
        "WISEACCT_PHASE7_FASTAPI_DATABASE_URL"
    ].replace("p7sf_", "wrong_")
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
    assert "validate_shared_result.py" in source
    assert "tree_is_clean_except_evidence" in source
    assert "concurrentTrialCount=70" in source
    assert "mixedRuntimeOverlapCount=70" in source
    assert "overlapMismatchCount=0" in source
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
    assert '[[ -n "${express_pid}" ]]' in source
    assert '[[ -n "${fastapi_pid}" ]]' in source
    assert '[[ ! -e "${PRIVATE_DIR}" && ! -L "${PRIVATE_DIR}" ]]' in source
    assert "artifacts_are_stable" in source
    assert '"(accessToken|refreshToken)"[[:space:]]*:' in source
    assert "|accessToken|refreshToken'" not in source
    assert "if ! publish_evidence" in source
    assert "launcher_exit=1" in source


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


def write_publish_bundle(root: Path, run_id: str = "shared_test_123") -> Path:
    staging = root / f".{run_id}.tmp.abcdefgh"
    staging.mkdir()
    (staging / "express-before.txt").write_text("same\n", encoding="utf-8")
    (staging / "express-after.txt").write_text("same\n", encoding="utf-8")
    (staging / "cleanup.status").write_text(
        "".join(f"{key}=PASS\n" for key in sorted(publisher.CLEANUP_KEYS)), encoding="utf-8"
    )
    (staging / "result.status").write_text(
        "status=PASS\nlauncherExit=0\ngateVerdict=PASS\ngateExit=0\nintegrity=PASS\n"
        "cleanup=PASS\n"
        "expressSnapshotUnchanged=true\nzeroCandidateResources=true\n"
        "privateTempRemoved=true\nresultCount=100\nconcurrentTrialCount=70\n"
        "mixedRuntimeOverlapCount=70\noverlapMismatchCount=0\n"
        "fullPhase7SampleSatisfied=false\noverallReplacementReady=false\n",
        encoding="utf-8",
    )
    (staging / "provenance.txt").write_text(
        f"gitHead={'a' * 40}\nrunId={run_id}\ngateEvidenceSha256={'b' * 64}\n"
        f"runtimeLauncherSha256={'c' * 64}\n",
        encoding="utf-8",
    )
    for path in staging.iterdir():
        path.chmod(0o444)
    staging.chmod(0o555)
    return staging


def test_publisher_accepts_only_complete_linked_pass_bundle(tmp_path: Path) -> None:
    staging = write_publish_bundle(tmp_path)
    publisher.validate_bundle(staging, "shared_test_123")


def test_publisher_rejects_pass_with_non_pass_cleanup(tmp_path: Path) -> None:
    staging = write_publish_bundle(tmp_path)
    cleanup = staging / "cleanup.status"
    staging.chmod(0o755)
    cleanup.chmod(0o644)
    cleanup.write_text(
        cleanup.read_text(encoding="utf-8").replace("clearRedis13=PASS", "clearRedis13=FAIL"),
        encoding="utf-8",
    )
    cleanup.chmod(0o444)
    staging.chmod(0o555)
    with pytest.raises(ValueError):
        publisher.validate_bundle(staging, "shared_test_123")


def test_publisher_accepts_correlated_fail_bundle(tmp_path: Path) -> None:
    staging = write_publish_bundle(tmp_path)
    cleanup = staging / "cleanup.status"
    result = staging / "result.status"
    staging.chmod(0o755)
    cleanup.chmod(0o644)
    cleanup.write_text(
        cleanup.read_text(encoding="utf-8").replace("clearRedis13=PASS", "clearRedis13=FAIL"),
        encoding="utf-8",
    )
    result.chmod(0o644)
    result.write_text(
        result.read_text(encoding="utf-8")
        .replace("status=PASS", "status=FAIL", 1)
        .replace("launcherExit=0", "launcherExit=1")
        .replace("cleanup=PASS", "cleanup=FAIL"),
        encoding="utf-8",
    )
    cleanup.chmod(0o444)
    result.chmod(0o444)
    staging.chmod(0o555)
    publisher.validate_bundle(staging, "shared_test_123")


def test_publisher_rejects_fail_bundle_with_zero_final_exit(tmp_path: Path) -> None:
    staging = write_publish_bundle(tmp_path)
    result = staging / "result.status"
    staging.chmod(0o755)
    result.chmod(0o644)
    result.write_text(
        result.read_text(encoding="utf-8").replace("status=PASS", "status=FAIL", 1),
        encoding="utf-8",
    )
    result.chmod(0o444)
    staging.chmod(0o555)
    with pytest.raises(ValueError, match="non-zero final launcher exit"):
        publisher.validate_bundle(staging, "shared_test_123")


def test_publisher_rejects_missing_overlap_or_provenance(tmp_path: Path) -> None:
    staging = write_publish_bundle(tmp_path)
    result = staging / "result.status"
    staging.chmod(0o755)
    result.chmod(0o644)
    result.write_text(
        result.read_text(encoding="utf-8").replace("mixedRuntimeOverlapCount=70\n", ""),
        encoding="utf-8",
    )
    result.chmod(0o444)
    staging.chmod(0o555)
    with pytest.raises(ValueError, match="exact approved fields"):
        publisher.validate_bundle(staging, "shared_test_123")

    other = write_publish_bundle(tmp_path, "shared_test_456")
    provenance = other / "provenance.txt"
    other.chmod(0o755)
    provenance.chmod(0o644)
    provenance.write_text("", encoding="utf-8")
    provenance.chmod(0o444)
    other.chmod(0o555)
    with pytest.raises(ValueError, match="provenance"):
        publisher.validate_bundle(other, "shared_test_456")


def test_publisher_rejects_final_directory_run_id_mismatch(tmp_path: Path) -> None:
    staging = write_publish_bundle(tmp_path)
    with pytest.raises(ValueError, match="not linked"):
        publisher.validate_bundle(staging, "different_run_123")


def test_publication_collision_returns_nonzero_after_valid_pass_bundle(tmp_path: Path) -> None:
    staging = write_publish_bundle(tmp_path)
    final = tmp_path / "shared_test_123"
    final.mkdir()
    completed = subprocess.run(  # noqa: S603 - fixed repository publisher path
        [str(PUBLISHER), "--staging", str(staging), "--final", str(final)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "publication refused" in completed.stderr


def write_validated_overlap_result(tmp_path: Path) -> tuple[Path, Path, Path]:
    scenarios = REPO / "contracts" / "scenarios" / "shared-state-core-v1.json"
    schedule_ids = [item["id"] for item in json.loads(scenarios.read_text())["scenarios"]]
    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(
            {
                "suiteId": "shared-state-core-v1",
                "status": "PASS",
                "plannedTrials": 100,
                "passedTrials": 100,
                "failedTrials": 0,
                "notRunTrials": 0,
                "fullPhase7SampleSatisfied": False,
                "overallReplacementReady": False,
            }
        ),
        encoding="utf-8",
    )
    jsonl = tmp_path / "results.jsonl"
    rows = []
    for schedule_id in schedule_ids:
        for trial in range(1, 11):
            evidence = {}
            if schedule_id in result_validator.CONCURRENT_SCHEDULES:
                evidence["mixedRuntimeRequestLifetimeOverlap"] = True
            rows.append(
                {
                    "suiteId": "shared-state-core-v1",
                    "scheduleId": schedule_id,
                    "trial": trial,
                    "attempt": 1,
                    "retryCount": 0,
                    "outcome": "PASS",
                    "evidence": evidence,
                    "fullPhase7SampleSatisfied": False,
                    "overallReplacementReady": False,
                }
            )
    jsonl.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return summary, jsonl, scenarios


def test_result_validator_requires_exact_seventy_overlap_trials(tmp_path: Path) -> None:
    summary, jsonl, scenarios = write_validated_overlap_result(tmp_path)
    result_validator.validate(summary, jsonl, scenarios)

    rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines()]
    rows[20]["evidence"].pop("mixedRuntimeRequestLifetimeOverlap")
    jsonl.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    with pytest.raises(ValueError, match="lacks mixed-runtime"):
        result_validator.validate(summary, jsonl, scenarios)
