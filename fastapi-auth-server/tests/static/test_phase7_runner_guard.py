import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
REPO = ROOT.parent
RUNNER = ROOT / "ops" / "run-phase7-qualification.sh"
VALIDATOR = ROOT / "ops" / "phase7" / "validate_inputs.py"
CONTRACT_GATE = ROOT / "ops" / "phase7" / "run-independent-contract-gate.sh"
PREFLIGHT = ROOT / "ops" / "phase7" / "run_adapter_preflights.py"
PLACEHOLDER_GATE = ROOT / "ops" / "phase7" / "run-placeholder-gate.sh"
GIT = shutil.which("git") or "/usr/bin/git"

EXPRESS_DB = "postgresql://phase7:synthetic@127.0.0.1:5433/express_contract_test"
FASTAPI_DB = "postgresql+asyncpg://phase7:synthetic@127.0.0.1:5434/fastapi_contract_test"
FASTAPI_NODE_DB = "postgresql://phase7:synthetic@127.0.0.1:5434/fastapi_contract_test"
EXPRESS_REDIS = "redis://127.0.0.1:6380/13"
FASTAPI_REDIS = "redis://127.0.0.1:6380/14"


def git_run(arguments: list[str], cwd: Path) -> None:
    subprocess.run([GIT, *arguments], cwd=cwd, check=True)  # noqa: S603


def write_config(path: Path, *, database: str, redis: str, fastapi: bool = False) -> None:
    value = {
        "CONTRACT_FIXTURE_MODE": "1",
        "CONTRACT_SERVER_MAIL_MODE": "dev",
        "CONTRACT_REDIS_ISOLATED_DB": "1",
        "CONTRACT_DATABASE_URL": database,
        "CONTRACT_REDIS_URL": redis,
        "CONTRACT_REFRESH_SECRET": "local-only-random-secret-value",
    }
    if fastapi:
        value["CONTRACT_FASTAPI_RUNTIME"] = "1"
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def safe_arguments(tmp_path: Path) -> tuple[list[str], dict[str, str]]:
    express_config = tmp_path / "express-source.json"
    fastapi_config = tmp_path / "fastapi-source.json"
    snapshot_dir = tmp_path / "private"
    snapshot_dir.mkdir(mode=0o700)
    write_config(express_config, database=EXPRESS_DB, redis=EXPRESS_REDIS)
    write_config(fastapi_config, database=FASTAPI_NODE_DB, redis=FASTAPI_REDIS, fastapi=True)
    arguments = [
        "--baseline",
        "http://127.0.0.1:4100",
        "--candidate",
        "http://localhost:4101",
        "--express-config",
        str(express_config),
        "--fastapi-config",
        str(fastapi_config),
        "--snapshot-dir",
        str(snapshot_dir),
        "--repo",
        str(REPO),
        "--evidence",
        str(ROOT / "evidence" / "phase7"),
    ]
    environment = {
        "PATH": os.environ["PATH"],
        "PYTHONDONTWRITEBYTECODE": "1",
        "WISEACCT_PHASE7_EXPRESS_DATABASE_URL": EXPRESS_DB,
        "WISEACCT_PHASE7_FASTAPI_DATABASE_URL": FASTAPI_DB,
        "WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL": FASTAPI_NODE_DB,
        "WISEACCT_PHASE7_EXPRESS_REDIS_URL": EXPRESS_REDIS,
        "WISEACCT_PHASE7_FASTAPI_REDIS_URL": FASTAPI_REDIS,
    }
    return arguments, environment


def validate(arguments: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed local validator and argument vector
        [sys.executable, str(VALIDATOR), *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def replace(arguments: list[str], option: str, value: str) -> None:
    arguments[arguments.index(option) + 1] = value


def test_validator_snapshots_once_and_emits_only_sanitized_topology(tmp_path: Path) -> None:
    arguments, environment = safe_arguments(tmp_path)
    express_source = Path(arguments[arguments.index("--express-config") + 1])
    result = validate(arguments, environment)

    assert result.returncode == 0, result.stderr
    topology = json.loads(result.stdout)
    assert topology["postgres"]["express"]["database"] == "express_contract_test"
    assert topology["redis"]["fastapi"]["database"] == 14
    assert topology["adapterConfigs"] == "private-snapshots-not-persisted"
    assert "synthetic" not in result.stdout
    snapshot = tmp_path / "private" / "express.json"
    original_snapshot = snapshot.read_bytes()
    express_source.write_text("mutated after snapshot", encoding="utf-8")
    assert snapshot.read_bytes() == original_snapshot
    assert snapshot.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "forbidden", ["PATH", "PYTHONPATH", "LD_PRELOAD", "PGHOST", "DATABASE_URL", "UNKNOWN"]
)
def test_validator_rejects_every_unapproved_adapter_environment_key(
    tmp_path: Path, forbidden: str
) -> None:
    arguments, environment = safe_arguments(tmp_path)
    express_source = Path(arguments[arguments.index("--express-config") + 1])
    document = json.loads(express_source.read_text(encoding="utf-8"))
    document[forbidden] = "must-not-be-loaded"
    express_source.write_text(json.dumps(document), encoding="utf-8")
    result = validate(arguments, environment)

    assert result.returncode == 2
    assert "unapproved environment keys" in result.stderr
    assert "must-not-be-loaded" not in result.stderr


def test_validator_requires_external_absolute_regular_0600_config(tmp_path: Path) -> None:
    arguments, environment = safe_arguments(tmp_path)
    express_source = Path(arguments[arguments.index("--express-config") + 1])
    express_source.chmod(0o644)
    result = validate(arguments, environment)
    assert result.returncode == 2
    assert "permission mode 0600" in result.stderr

    express_source.chmod(0o600)
    replace(arguments, "--express-config", "relative.json")
    assert validate(arguments, environment).returncode == 2


def test_sensitive_urls_are_environment_only_not_validator_argv() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    invocation = source[source.index('topology="$(${PHASE7_DIR}/validate_inputs.py') :]
    invocation = invocation[: invocation.index(')"')]
    assert "--express-database" not in invocation
    assert "--fastapi-database" not in invocation
    assert "--express-redis" not in invocation
    assert "--fastapi-redis" not in invocation
    assert "WISEACCT_PHASE7_EXPRESS_DATABASE_URL" not in invocation
    assert "WISEACCT_PHASE7_EXPRESS_REDIS_URL" not in invocation


def make_fake_gate_tree(
    tmp_path: Path, *, express_fails: bool = False
) -> tuple[Path, Path, Path, Path]:
    phase7 = tmp_path / "fastapi-auth-server" / "ops" / "phase7"
    adapters = tmp_path / "contracts" / "adapters"
    scenarios = tmp_path / "contracts" / "scenarios"
    binaries = tmp_path / "contracts" / "bin"
    for directory in (phase7, adapters, scenarios, binaries):
        directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CONTRACT_GATE, phase7 / CONTRACT_GATE.name)
    shutil.copy2(PREFLIGHT, phase7 / PREFLIGHT.name)
    marker = tmp_path / "events.log"
    for runtime in ("express", "fastapi"):
        failure = "sys.exit(1)" if runtime == "express" and express_fails else ""
        adapter = adapters / f"{runtime}_fixture.py"
        adapter.write_text(
            "#!/usr/bin/env python3\nimport json,sys\n"
            f"open({str(marker)!r},'a').write({runtime!r}+':'+sys.argv[1]+'\\n')\n"
            f"{failure}\nprint(json.dumps({{'status':'ok','database':'synthetic_test','redisDatabase':9}}))\n",
            encoding="utf-8",
        )
        adapter.chmod(0o755)
    differential = binaries / "differential.py"
    differential.write_text(
        "#!/usr/bin/env python3\nimport json,sys\nfrom pathlib import Path\n"
        f"open({str(marker)!r},'a').write('http\\n')\n"
        "args=sys.argv; out=Path(args[args.index('--jsonl')+1]); "
        "src=Path(args[args.index('--scenarios')+1]); "
        "n=len(json.loads(src.read_text())['scenarios']); "
        'out.write_text(\'{"outcome":"pass"}\\n\'*n)\n',
        encoding="utf-8",
    )
    for suite in ("public", "guards", "fixtures"):
        (scenarios / f"{suite}.json").write_text(
            json.dumps({"version": 1, "scenarios": [{"id": suite}]}), encoding="utf-8"
        )
    git_run(["init", "-q"], tmp_path)
    git_run(["config", "user.email", "phase7@example.invalid"], tmp_path)
    git_run(["config", "user.name", "Phase7"], tmp_path)
    git_run(["add", "."], tmp_path)
    git_run(["commit", "-qm", "synthetic"], tmp_path)
    express_config, fastapi_config = tmp_path / "express.json", tmp_path / "fastapi.json"
    express_config.write_text("{}", encoding="utf-8")
    fastapi_config.write_text("{}", encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    return phase7 / CONTRACT_GATE.name, express_config, fastapi_config, evidence


@pytest.mark.parametrize("express_fails", [False, True])
def test_both_preflights_run_before_any_http_and_failure_runs_zero_suites(
    tmp_path: Path, express_fails: bool
) -> None:
    gate, express_config, fastapi_config, evidence = make_fake_gate_tree(
        tmp_path, express_fails=express_fails
    )
    result = subprocess.run(  # noqa: S603 - isolated synthetic gate tree
        [
            str(gate),
            "http://127.0.0.1:4100",
            "http://127.0.0.1:4101",
            str(express_config),
            str(fastapi_config),
            str(evidence),
        ],
        env={"PATH": os.environ["PATH"]},
        check=False,
        capture_output=True,
        text=True,
    )
    events = (tmp_path / "events.log").read_text(encoding="utf-8").splitlines()
    assert events[:2] == ["express:preflight", "fastapi:preflight"]
    if express_fails:
        assert result.returncode != 0
        assert events == ["express:preflight", "fastapi:preflight"]
        assert all(
            "status=NOT_RUN" in (evidence / f"{suite}.status").read_text()
            for suite in ("public", "guards", "fixtures")
        )
    else:
        assert result.returncode == 0, result.stderr
        assert events[2:] == ["http", "http", "http"]


def test_runner_preserves_snapshot_stability_fail_fast_and_incomplete_status() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    gate = CONTRACT_GATE.read_text(encoding="utf-8")
    assert "mktemp -d /tmp/wiseacct-phase7." in source
    assert "snapshots_are_stable" in source
    assert "passedGate=independent-contract" in source
    assert "status=INCOMPLETE" in source and "overallReplacementReady=false" in source
    assert gate.index("run_adapter_preflights.py") < gate.index("differential.py")
    assert "for suite in public guards fixtures" in gate
    assert "--baseline-adapter-preflight" not in gate
    assert 'exit "${status}"' in gate


def test_phase7_runner_has_no_production_mutation_commands() -> None:
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [RUNNER, *(ROOT / "ops" / "phase7").glob("*.sh")]
    )
    forbidden = (
        "docker compose",
        "kubectl",
        "systemctl",
        "nginx",
        "DROP DATABASE",
        "FLUSHALL",
        "FLUSHDB",
    )
    assert all(command not in sources for command in forbidden)


def test_phase7_placeholder_is_explicitly_incomplete(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed local placeholder gate
        [str(PLACEHOLDER_GATE), "security", str(tmp_path)],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"]},
        check=False,
    )
    assert result.returncode == 3
    assert "status=SKIP" in (tmp_path / "security.status").read_text(encoding="utf-8")
