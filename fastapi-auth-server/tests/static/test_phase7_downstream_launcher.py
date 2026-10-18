"""Execute the real top-level shell against an isolated synthetic contract gate."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
RUNNER = ROOT / "ops/run-phase7-qualification.sh"
GIT = shutil.which("git") or "/usr/bin/git"


def write(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(0o700)


@pytest.mark.parametrize(
    "child_exit,expected_exit,mutate_source",
    [(3, 3, False), (2, 2, False), (0, 2, False), (130, 2, False), (3, 5, True)],
)
def test_top_runner_calls_downstream_and_never_promotes_success(
    tmp_path: Path, child_exit: int, expected_exit: int, mutate_source: bool
) -> None:
    repo = tmp_path / "repo"
    phase7 = repo / "fastapi-auth-server/ops/phase7"
    phase7.mkdir(parents=True)
    runner = phase7.parent / RUNNER.name
    shutil.copy2(RUNNER, runner)
    write(repo / "fastapi-auth-server/.env.example", "synthetic=true\n")
    write(repo / "contracts/bin/differential.py", "# synthetic contract runner\n")
    for name in ("public", "guards", "fixtures"):
        write(repo / f"contracts/scenarios/{name}.json", "{}\n")
    write(phase7 / "runtime_public_scenarios.py", "# no runtime override\n")
    write(
        phase7 / "validate_inputs.py",
        "#!/usr/bin/python3\n"
        "import sys\nfrom pathlib import Path\n"
        "p=Path(sys.argv[sys.argv.index('--snapshot-dir')+1])\n"
        "(p/'express.json').write_text('{}')\n"
        "(p/'fastapi.json').write_text('{}')\nprint('{}')\n",
        executable=True,
    )
    write(phase7 / "run-independent-contract-gate.sh", "#!/bin/sh\nexit 0\n", executable=True)
    write(
        phase7 / "run_downstream_gates.py",
        "import json,os,sys\nfrom pathlib import Path\n"
        "p=Path(sys.argv[sys.argv.index('--evidence-dir')+1])\n"
        "(p/'invocation.json').write_text(json.dumps({'args':sys.argv[1:],"
        "'environmentKeys':sorted(os.environ)}))\n"
        f"if {mutate_source!r}: Path(__file__).write_text('# changed during run\\n')\n"
        f"raise SystemExit({child_exit})\n",
    )
    for arguments in (
        ["init", "-q"],
        ["config", "user.email", "contract@example.invalid"],
        ["config", "user.name", "Contract"],
        ["add", "."],
        ["commit", "-qm", "synthetic"],
    ):
        subprocess.run([GIT, *arguments], cwd=repo, check=True, capture_output=True)  # noqa: S603
    revision, tree = [
        subprocess.run(  # noqa: S603 - fixed Git object queries in synthetic tree
            [GIT, "rev-parse", reference], cwd=repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        for reference in ("HEAD", "HEAD^{tree}")
    ]
    security_input = tmp_path / "security input"
    backup_input = tmp_path / "backup input"
    environment = {
        "PATH": os.environ["PATH"],
        "WISEACCT_PHASE7_RUN_ID": "downstream-test",
        "WISEACCT_PHASE7_SECURITY_INPUT_DIR": str(security_input),
        "WISEACCT_PHASE7_BACKUP_RESTORE_INPUT_DIR": str(backup_input),
        "PRIVATE_TEST_SECRET": "must-not-reach-child",
    }
    for name in (
        "BASELINE_URL",
        "CANDIDATE_URL",
        "EXPRESS_DATABASE_URL",
        "FASTAPI_DATABASE_URL",
        "FASTAPI_NODE_DATABASE_URL",
        "EXPRESS_REDIS_URL",
        "FASTAPI_REDIS_URL",
        "EXPRESS_ADAPTER_CONFIG",
        "FASTAPI_ADAPTER_CONFIG",
    ):
        environment[f"WISEACCT_PHASE7_{name}"] = "synthetic"
    result = subprocess.run(  # noqa: S603 - real shell in committed synthetic tree
        ["/bin/bash", str(runner)],
        cwd=repo,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == expected_exit, result.stderr
    evidence = repo / "fastapi-auth-server/evidence/phase7/downstream-test"
    status = (evidence / "result.status").read_text()
    assert "overallReplacementReady=false" in status
    assert "status=PASS" not in status
    assert ("status=INCOMPLETE" if expected_exit == 3 else "status=FAIL") in status
    if mutate_source:
        assert "failedGate=provenance-stability" in status
    assert "downstreamRunnerSha256=" in (evidence / "provenance.txt").read_text()
    invocation = json.loads((evidence / "invocation.json").read_text())
    assert invocation["args"] == [
        "--evidence-dir",
        str(evidence),
        "--run-id",
        "downstream-test",
        "--source-revision",
        revision,
        "--source-tree",
        tree,
        "--security-input",
        str(security_input),
        "--backup-restore-input",
        str(backup_input),
    ]
    assert set(invocation["environmentKeys"]) <= {"PATH", "LC_CTYPE"}
    assert "must-not-reach-child" not in result.stdout + result.stderr
    assert not (evidence.stat().st_mode & 0o222)
