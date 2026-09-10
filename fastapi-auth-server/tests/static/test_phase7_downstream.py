from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT.parent
RUNNER = ROOT / "ops" / "phase7" / "run_downstream_gates.py"
SPEC = importlib.util.spec_from_file_location("phase7_downstream", RUNNER)
assert SPEC is not None and SPEC.loader is not None
downstream = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = downstream
SPEC.loader.exec_module(downstream)
SECURITY_TEST = ROOT / "tests" / "static" / "test_phase7_security_gate.py"
SECURITY_SPEC = importlib.util.spec_from_file_location("phase7_security_test_helper", SECURITY_TEST)
assert SECURITY_SPEC is not None and SECURITY_SPEC.loader is not None
security_test = importlib.util.module_from_spec(SECURITY_SPEC)
sys.modules[SECURITY_SPEC.name] = security_test
SECURITY_SPEC.loader.exec_module(security_test)


def git_object(repo: Path, expression: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed Git with bounded test expressions
        ["/usr/bin/git", "-C", str(repo), "rev-parse", expression],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


SOURCE_REVISION = git_object(REPO, "HEAD")
SOURCE_TREE = git_object(REPO, "HEAD^{tree}")


@pytest.fixture(autouse=True)
def restore_process_umask() -> Any:
    original = os.umask(0o077)
    os.umask(original)
    try:
        yield
    finally:
        os.umask(original)


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700)
    return path


def invoke(
    evidence: Path, *extra: str, run_id: str = "downstream-test"
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed repository CLI under test
        [
            "/usr/bin/python3",
            "-I",
            str(RUNNER),
            "--evidence-dir",
            str(evidence),
            "--run-id",
            run_id,
            "--source-revision",
            SOURCE_REVISION,
            "--source-tree",
            SOURCE_TREE,
            *extra,
        ],
        cwd=REPO,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        capture_output=True,
        text=True,
    )


def read_statuses(evidence: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for gate in downstream.GATES:
        lines = (evidence / f"{gate}.status").read_text(encoding="utf-8").splitlines()
        result[gate] = dict(line.split("=", 1) for line in lines)
    return result


def test_no_inputs_publishes_five_fixed_nonqualifying_statuses(tmp_path: Path) -> None:
    evidence = private_dir(tmp_path / "evidence")
    completed = invoke(evidence)

    assert completed.returncode == 3, completed.stderr
    statuses = read_statuses(evidence)
    assert set(statuses) == set(downstream.GATES)
    assert statuses["security"]["status"] == "SKIP"
    assert statuses["security"]["reason"] == "INPUT_REQUIRED"
    assert statuses["backup-restore"]["status"] == "SKIP"
    assert statuses["performance"]["reason"] == "NOT_IMPLEMENTED"
    assert statuses["chaos"]["reason"] == "NOT_IMPLEMENTED"
    assert statuses["local-rollback"]["reason"] == "NOT_IMPLEMENTED"
    assert all(value["overallReplacementReady"] == "false" for value in statuses.values())
    assert not (evidence / "downstream").exists()


@pytest.mark.parametrize(
    ("option", "gate"),
    [("--security-input", "security"), ("--backup-restore-input", "backup-restore")],
)
def test_real_child_cli_missing_bundle_files_publishes_genuine_incomplete(
    tmp_path: Path, option: str, gate: str
) -> None:
    evidence = private_dir(tmp_path / "evidence")
    source = private_dir(tmp_path / "input")

    completed = invoke(evidence, option, str(source))

    assert completed.returncode == 3, completed.stderr
    statuses = read_statuses(evidence)
    assert statuses[gate]["status"] == "INCOMPLETE"
    assert statuses[gate]["reason"] == "MISSING_EVIDENCE"
    child = evidence / "downstream" / gate / "downstream-test"
    result = json.loads((child / "gate-result.json").read_text(encoding="utf-8"))
    assert result["status"] == "INCOMPLETE"
    assert result["overallReplacementReady"] is False
    assert "status=INCOMPLETE" in (child / "result.status").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("option", "gate"),
    [("--security-input", "security"), ("--backup-restore-input", "backup-restore")],
)
def test_real_child_cli_rejects_bad_bundle_without_leaking_child_text(
    tmp_path: Path, option: str, gate: str
) -> None:
    evidence = private_dir(tmp_path / "evidence")
    source = private_dir(tmp_path / "input")
    sentinel = "private-child-sentinel"
    unexpected = source / "unexpected-private.txt"
    unexpected.write_text(sentinel, encoding="utf-8")
    unexpected.chmod(0o600)

    completed = invoke(evidence, option, str(source))

    assert completed.returncode == 2
    assert sentinel not in completed.stdout
    assert sentinel not in completed.stderr
    statuses = read_statuses(evidence)
    assert statuses[gate]["status"] == "FAIL"
    assert statuses[gate]["reason"] == "MALFORMED_INPUT"
    assert all(value["status"] != "PASS" for value in statuses.values())


def publish_fake_child(root: Path, gate: str, run_id: str, status: str = "INCOMPLETE") -> None:
    output = root / run_id
    output.mkdir(mode=0o700)
    reason = "MISSING_EVIDENCE"
    status_path = output / "result.status"
    status_path.write_text(
        f"status={status}\noverallReplacementReady=false\nreasonCodes={reason}\n",
        encoding="utf-8",
    )
    result_path = output / "gate-result.json"
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "gateId": gate,
                "runId": run_id,
                "status": status,
                "sampleSatisfied": status == "PASS",
                "readinessAssertionsSatisfied": status == "PASS",
                "cleanupComplete": status == "PASS",
                "expressSnapshotUnchanged": status == "PASS",
                "overallReplacementReady": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    status_path.chmod(0o400)
    result_path.chmod(0o400)
    output.chmod(0o500)


def test_dispatch_uses_fixed_command_clean_environment_and_suppressed_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = private_dir(tmp_path / "evidence")
    source = private_dir(tmp_path / "input")
    observed: dict[str, Any] = {}

    def fake_run(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        observed.update(arguments=arguments, kwargs=kwargs)
        root = Path(arguments[arguments.index("--evidence-root") + 1])
        publish_fake_child(root, "backup-restore", "fixed-test")
        return subprocess.CompletedProcess(arguments, 3)

    monkeypatch.setattr(downstream.subprocess, "run", fake_run)
    result = downstream.main(
        [
            "--evidence-dir",
            str(evidence),
            "--run-id",
            "fixed-test",
            "--source-revision",
            SOURCE_REVISION,
            "--source-tree",
            SOURCE_TREE,
            "--backup-restore-input",
            str(source),
        ]
    )

    assert result == 3
    arguments = observed["arguments"]
    assert arguments[:2] == ["/usr/bin/python3", "-I"]
    assert arguments[2] == str(
        REPO / "fastapi-auth-server/ops/phase7/backup_restore/backup_restore_gate.py"
    )
    kwargs = observed["kwargs"]
    assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["timeout"] == downstream.TIMEOUT_SECONDS


@pytest.mark.parametrize(
    ("child_status", "child_exit", "mutation", "reason"),
    [
        ("PASS", 0, None, "QUALIFYING_RESULT_REFUSED"),
        ("INCOMPLETE", 2, None, "DOWNSTREAM_EXIT_MISMATCH"),
        ("INCOMPLETE", 3, "malformed", "DOWNSTREAM_RESULT_MALFORMED"),
        ("INCOMPLETE", 3, "bool-integer", "DOWNSTREAM_RESULT_MALFORMED"),
        ("INCOMPLETE", 3, "duplicate", "DOWNSTREAM_RESULT_MALFORMED"),
    ],
)
def test_forged_pass_exit_mismatch_and_malformed_results_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    child_status: str,
    child_exit: int,
    mutation: str | None,
    reason: str,
) -> None:
    evidence = private_dir(tmp_path / "evidence")
    source = private_dir(tmp_path / "input")

    def fake_run(arguments: list[str], **_: Any) -> subprocess.CompletedProcess[bytes]:
        root = Path(arguments[arguments.index("--evidence-root") + 1])
        publish_fake_child(root, "backup-restore", "failure-test", child_status)
        if mutation:
            result = root / "failure-test" / "gate-result.json"
            result.chmod(0o600)
            if mutation == "malformed":
                result.write_text("{}\n", encoding="utf-8")
            elif mutation == "bool-integer":
                document = json.loads(result.read_text(encoding="utf-8"))
                document["schemaVersion"] = True
                document["sampleSatisfied"] = 0
                result.write_text(json.dumps(document), encoding="utf-8")
            else:
                payload = result.read_text(encoding="utf-8")
                duplicate = payload.replace(
                    '"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'
                )
                result.write_text(duplicate)
            result.chmod(0o400)
        return subprocess.CompletedProcess(arguments, child_exit)

    monkeypatch.setattr(downstream.subprocess, "run", fake_run)
    result = downstream.main(
        [
            "--evidence-dir",
            str(evidence),
            "--run-id",
            "failure-test",
            "--source-revision",
            SOURCE_REVISION,
            "--source-tree",
            SOURCE_TREE,
            "--backup-restore-input",
            str(source),
        ]
    )

    assert result == 2
    statuses = read_statuses(evidence)
    assert statuses["backup-restore"] == {
        "gate": "backup-restore",
        "status": "FAIL",
        "reason": reason,
        "overallReplacementReady": "false",
    }
    assert all(value["status"] != "PASS" for value in statuses.values())


def test_unsafe_paths_run_ids_reuse_and_input_overlap_are_rejected_before_writes(
    tmp_path: Path,
) -> None:
    evidence = private_dir(tmp_path / "evidence")
    source = private_dir(tmp_path / "input")
    symlink = tmp_path / "evidence-link"
    symlink.symlink_to(evidence, target_is_directory=True)

    assert invoke(symlink).returncode == 2
    assert invoke(evidence, run_id="../unsafe").returncode == 2
    assert invoke(evidence, "--security-input", str(evidence)).returncode == 2
    assert not list(evidence.iterdir())

    first = invoke(evidence, "--security-input", str(source))
    assert first.returncode == 3
    second = invoke(evidence, "--security-input", str(source))
    assert second.returncode == 2
    assert len(list(evidence.glob("*.status"))) == 5


def test_security_complete_bundle_uses_clean_same_source_clone_and_cleans_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = private_dir(tmp_path / "fixture")
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    monkeypatch.setattr(security_test, "NOW", now)
    monkeypatch.setattr(security_test, "NOW_TEXT", now.isoformat().replace("+00:00", "Z"))
    source, repo = security_test.make_input(fixture)
    evidence = private_dir(repo / "qualification-evidence")
    (evidence / "downstream").mkdir(mode=0o700)
    revision = git_object(repo, "HEAD")
    tree = git_object(repo, "HEAD^{tree}")
    temp_root = Path(tempfile.gettempdir())
    mirrors_before = set(temp_root.glob("wiseacct-phase7-security-source.*"))

    result = downstream.run_gate(
        "security", source, evidence, "security-test", repo, revision, tree
    )

    assert result == downstream.GateStatus(
        "security",
        "INCOMPLETE",
        "TOOLCHAIN_LOCK_UNFROZEN,CONTROLLED_COLLECTOR_REQUIRED",
    )
    assert git_object(repo, "HEAD") == revision
    assert git_object(repo, "HEAD^{tree}") == tree
    assert set(temp_root.glob("wiseacct-phase7-security-source.*")) == mirrors_before
    assert (evidence / "downstream/security/security-test/gate-result.json").is_file()


def test_security_source_mismatch_fails_and_cleans_clone(tmp_path: Path) -> None:
    source = private_dir(tmp_path / "input")
    evidence = private_dir(tmp_path / "evidence")
    (evidence / "downstream").mkdir(mode=0o700)
    temp_root = Path(tempfile.gettempdir())
    mirrors_before = set(temp_root.glob("wiseacct-phase7-security-source.*"))

    result = downstream.run_gate(
        "security", source, evidence, "mismatch-test", REPO, "0" * 40, SOURCE_TREE
    )

    assert result == downstream.GateStatus("security", "FAIL", "SOURCE_BINDING_MISMATCH")
    assert set(temp_root.glob("wiseacct-phase7-security-source.*")) == mirrors_before
