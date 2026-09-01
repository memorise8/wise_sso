from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT.parent
LAUNCHER = ROOT / "ops" / "run-phase7-independent-integration.sh"
QUALIFICATION = ROOT / "ops" / "run-phase7-qualification.sh"
MATERIAL = ROOT / "ops" / "phase7" / "runtime_material.py"
RUNTIME_EXEC = ROOT / "ops" / "phase7" / "runtime_exec.py"
REDIS_CLEAR = ROOT / "ops" / "phase7" / "runtime_redis_clear.py"
CANDIDATE_STATE = ROOT / "ops" / "phase7" / "runtime_candidate_state.py"
LISTEN_GUARD = ROOT / "ops" / "phase7" / "runtime_listen_guard.py"
PUBLISH = ROOT / "ops" / "phase7" / "runtime_publish.py"
PRIVATE_REMOVE = ROOT / "ops" / "phase7" / "runtime_private_remove.py"
EXPRESS_LOOPBACK = ROOT / "ops" / "phase7" / "runtime_express_loopback.mjs"


def test_launcher_uses_exact_disposable_targets_and_guarded_compose() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    assert "readonly EXPRESS_PORT=4410" in source
    assert "readonly FASTAPI_PORT=4411" in source
    assert 'runtime_redis_clear.py" --database 13' in source
    assert 'runtime_redis_clear.py" --database 14' in source
    assert '"${SCRIPT_DIR}/dev-compose.sh" up "${ENV_EXAMPLE}"' in source
    assert '"${SCRIPT_DIR}/dev-compose.sh" down "${ENV_EXAMPLE}"' in source
    assert "wiseacct-sso-fastapi-dev" in source
    assert "CREATE DATABASE" in source and "DROP DATABASE IF EXISTS" in source
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT" in source
    assert "GRANT SELECT, INSERT, UPDATE, DELETE" in source


def test_cleanup_order_is_runtime_database_role_redis_compose_verify_publish() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    cleanup = source[source.index("cleanup() {") : source.index("trap cleanup EXIT")]
    positions = [
        cleanup.index('terminate_runtime "${express_pid}"'),
        cleanup.index("DROP DATABASE IF EXISTS"),
        cleanup.index("DROP ROLE IF EXISTS"),
        cleanup.index('runtime_redis_clear.py" --database 13'),
        cleanup.index('dev-compose.sh" down'),
        cleanup.index('snapshot_express "${after_snapshot}"'),
        cleanup.index("if candidate_resources_state; then"),
        cleanup.index('publish_evidence "${final_status}"'),
    ]
    assert positions == sorted(positions)
    assert source.index("compose_up_attempted=1") < source.index('dev-compose.sh" up')
    assert "if (( compose_up_attempted == 1 )); then" in cleanup


def test_launcher_has_no_production_mutation_or_network_call() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    forbidden = (
        "kubectl",
        "systemctl",
        "nginx",
        "docker service",
        "docker stack",
        "192.168.",
        "financenow.kr/health",
        "temis.me/health",
        "FLUSHALL",
        "FLUSHDB",
    )
    assert all(value not in source for value in forbidden)
    assert 'curl --fail --silent --show-error --output /dev/null "${origin}/healthz"' in source
    assert 'OAUTH_ENABLED_PROVIDERS": ""' in MATERIAL.read_text(encoding="utf-8")
    assert '"MAIL_PROVIDER": "dev"' in MATERIAL.read_text(encoding="utf-8")


def test_lock_is_inherited_and_verified_before_qualification() -> None:
    launcher = LAUNCHER.read_text(encoding="utf-8")
    qualification = QUALIFICATION.read_text(encoding="utf-8")
    assert 'exec 8>"${INTEGRATION_LOCK}"' in launcher
    assert "flock --nonblock 8" in launcher
    assert "WISEACCT_PHASE7_INTEGRATION_LOCK_FD=8" in launcher
    assert 'readlink -f -- "/proc/$$/fd/${INHERITED_LOCK_FD}"' in qualification
    assert 'flock --nonblock "${INHERITED_LOCK_FD}"' in qualification
    assert '"${INTEGRATION_LOCK}"' in qualification


def test_exit_three_requires_exact_incomplete_independent_gate_proof() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    proof = source[source.index("if (( qualification_exit == 3 ))") :]
    assert "grep -Fxq 'status=INCOMPLETE'" in proof
    assert "grep -Fxq 'passedGate=independent-contract'" in proof
    assert proof.index("status=INCOMPLETE") < proof.index('qualification_verdict="INCOMPLETE')
    assert "qualification_exit == 0" in proof and "grep -Fxq 'status=PASS'" in proof


def test_private_material_has_distinct_stores_shared_policy_and_exact_modes(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    result = subprocess.run(  # noqa: S603 - fixed local helper and argument vector
        [
            sys.executable,
            str(MATERIAL),
            "--example",
            str(ROOT / ".env.example"),
            "--private-dir",
            str(private),
            "--run-id",
            "20260901t010203_123",
            "--express-port",
            "4410",
            "--fastapi-port",
            "4411",
        ],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"]},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    express_env = json.loads((private / "express-runtime.json").read_text())
    fastapi_env = json.loads((private / "fastapi-runtime.json").read_text())
    express_adapter = json.loads((private / "express-adapter.json").read_text())
    fastapi_adapter = json.loads((private / "fastapi-adapter.json").read_text())
    assert express_env["DATABASE_URL"] != fastapi_env["DATABASE_URL"]
    assert express_env["REDIS_URL"].endswith("/13")
    assert fastapi_env["REDIS_URL"].endswith("/14")
    for key in (
        "JWT_ACCESS_PRIVATE_KEY",
        "JWT_ACCESS_PUBLIC_JWK",
        "JWT_ACCESS_KEY_ID",
        "JWT_ISSUER",
        "AUTH_CLIENTS_JSON",
        "JWT_REFRESH_SECRET",
    ):
        assert express_env[key] == fastapi_env[key]
    assert express_env["OAUTH_ENABLED_PROVIDERS"] == ""
    assert express_env["WISEACCT_PHASE7_EXPRESS_LOOPBACK"] == "1"
    assert fastapi_env["MAIL_PROVIDER"] == "dev"
    assert express_adapter["CONTRACT_REDIS_URL"].endswith("/13")
    assert fastapi_adapter["CONTRACT_REDIS_URL"].endswith("/14")
    assert fastapi_adapter["CONTRACT_FASTAPI_RUNTIME"] == "1"
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in private.iterdir())
    assert "synthetic-fastapi-refresh-secret-only" not in json.dumps(express_adapter)
    settings_check = subprocess.run(  # noqa: S603 - fixed local helper and argument vector
        [
            sys.executable,
            str(RUNTIME_EXEC),
            str(private / "fastapi-runtime.json"),
            sys.executable,
            "-c",
            (
                "from wiseacct_sso.config import get_settings; "
                "s=get_settings(); "
                "assert s.port == 4411 and s.mail_provider == 'dev' "
                "and not s.oauth_enabled_providers"
            ),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert settings_check.returncode == 0, settings_check.stderr


def test_runtime_exec_rejects_non_private_environment(tmp_path: Path) -> None:
    environment = tmp_path / "environment.json"
    environment.write_text("{}", encoding="utf-8")
    environment.chmod(0o644)
    result = subprocess.run(  # noqa: S603 - fixed local helper and argument vector
        [sys.executable, str(RUNTIME_EXEC), str(environment), sys.executable, "-c", "pass"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "0600" in result.stderr


def test_redis_cleanup_is_pinned_to_only_databases_13_and_14() -> None:
    source = REDIS_CLEAR.read_text(encoding="utf-8")
    assert "choices=(13, 14)" in source
    assert 'command(stream, "SELECT", str(args.database))' in source
    assert 'command(stream, "UNLINK"' in source
    assert "FLUSH" not in source


def test_evidence_is_published_after_cleanup_without_runtime_logs_or_secrets() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    publish = source[source.index("publish_evidence() {") : source.index("cleanup() {")]
    assert "qualificationEvidenceSha256" in publish
    assert "overallReplacementReady=false" in publish
    assert "runtime.log" not in publish and "qualification.log" not in publish
    assert "PASSWORD" not in publish and "DATABASE_URL" not in publish
    assert 'chmod -R a-w -- "${evidence_staging}"' in publish
    assert (
        'runtime_publish.py" --staging "${evidence_staging}" --final '
        '"${RUNTIME_EVIDENCE_DIR}"' in publish
    )


def make_fake_docker(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir()
    binary = tmp_path / "docker"
    calls = tmp_path / "calls"
    binary.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >>"$FAKE_DOCKER_CALLS"\n'
        'case "$FAKE_DOCKER_MODE" in\n'
        "  error) exit 41 ;;\n"
        '  present) [ "$1" = ps ] && echo wiseacct-sso-fastapi-dev-app; exit 0 ;;\n'
        "  redis)\n"
        '    case "$1" in\n'
        "      ps) echo wiseacct-sso-fastapi-dev-redis ;;\n"
        '      inspect) echo "/wiseacct-sso-fastapi-dev-redis|true|wiseacct-sso-fastapi-dev" ;;\n'
        "      exec) echo PONG ;;\n"
        "    esac\n"
        "    exit 0 ;;\n"
        "  *) exit 0 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary, calls


def run_candidate_state(
    tmp_path: Path, mode: str, command: str = "resources"
) -> tuple[int, str, list[str]]:
    _, calls = make_fake_docker(tmp_path)
    result = subprocess.run(  # noqa: S603 - fixed local helper with a synthetic Docker executable
        [sys.executable, str(CANDIDATE_STATE), command],
        env={
            "PATH": str(tmp_path),
            "FAKE_DOCKER_MODE": mode,
            "FAKE_DOCKER_CALLS": str(calls),
        },
        check=False,
        capture_output=True,
        text=True,
    )
    recorded = calls.read_text(encoding="utf-8").splitlines()
    return result.returncode, result.stdout.strip(), recorded


def test_candidate_resource_inspection_distinguishes_empty_present_and_error(
    tmp_path: Path,
) -> None:
    empty = run_candidate_state(tmp_path / "empty", "empty")
    present = run_candidate_state(tmp_path / "present", "present")
    error = run_candidate_state(tmp_path / "error", "error")
    assert empty[:2] == (0, "EMPTY") and len(empty[2]) == 3
    assert present[:2] == (1, "PRESENT") and len(present[2]) == 3
    assert error[:2] == (2, "ERROR") and len(error[2]) == 1


def test_candidate_redis_probe_requires_exact_usable_runtime(tmp_path: Path) -> None:
    usable = run_candidate_state(tmp_path / "usable", "redis", "redis-usable")
    absent = run_candidate_state(tmp_path / "absent", "empty", "redis-usable")
    error = run_candidate_state(tmp_path / "error", "error", "redis-usable")
    assert usable[:2] == (0, "USABLE") and len(usable[2]) == 3
    assert absent[:2] == (1, "ABSENT") and len(absent[2]) == 1
    assert error[:2] == (2, "ERROR") and len(error[2]) == 1


def test_listen_guard_requires_socket_owned_by_exact_pid_and_port() -> None:
    server = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import os,socket,time; s=socket.socket(); "
                "s.bind(('127.0.0.1',0)); s.listen(); "
                "print(f'{os.getpid()} {s.getsockname()[1]}',flush=True); time.sleep(30)"
            ),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert server.stdout is not None
        pid_text, port_text = server.stdout.readline().split()
        pid, port = int(pid_text), int(port_text)
        unused_port = 4412 if port != 4412 else 4413
        good = subprocess.run(  # noqa: S603 - fixed local helper
            [sys.executable, str(LISTEN_GUARD), "--pid", str(pid), "--port", str(port)],
            check=False,
        )
        wrong_port = subprocess.run(  # noqa: S603 - fixed local helper
            [sys.executable, str(LISTEN_GUARD), "--pid", str(pid), "--port", str(unused_port)],
            check=False,
        )
        wrong_pid = subprocess.run(  # noqa: S603 - fixed local helper
            [sys.executable, str(LISTEN_GUARD), "--pid", str(os.getpid()), "--port", str(port)],
            check=False,
        )
        assert good.returncode == 0
        assert wrong_port.returncode == 1
        assert wrong_pid.returncode == 1
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_listen_guard_rejects_wildcard_listener_owned_by_exact_pid() -> None:
    server = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import os,socket,time; s=socket.socket(); "
                "s.bind(('0.0.0.0',0)); s.listen(); "
                "print(f'{os.getpid()} {s.getsockname()[1]}',flush=True); time.sleep(30)"
            ),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert server.stdout is not None
        pid_text, port_text = server.stdout.readline().split()
        result = subprocess.run(  # noqa: S603 - fixed local helper
            [
                sys.executable,
                str(LISTEN_GUARD),
                "--pid",
                pid_text,
                "--port",
                port_text,
            ],
            check=False,
        )
        assert result.returncode == 1
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_express_dedicated_launcher_forces_loopback_and_refuses_wildcard(tmp_path: Path) -> None:
    fixture = tmp_path / "server.mjs"
    fixture.write_text(
        "import net from 'node:net';\n"
        "const server=net.createServer();\n"
        "server.listen(Number(process.env.TEST_PORT),()=>console.log('ready'));\n",
        encoding="utf-8",
    )
    with __import__("socket").socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = subprocess.Popen(  # noqa: S603 - fixed dedicated launcher and synthetic module
        ["node", str(EXPRESS_LOOPBACK), str(fixture)],  # noqa: S607 - repository test runtime
        env={
            "PATH": os.environ["PATH"],
            "WISEACCT_PHASE7_EXPRESS_LOOPBACK": "1",
            "TEST_PORT": str(port),
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert server.stdout is not None
        assert server.stdout.readline().strip() == "ready"
        guard = subprocess.run(  # noqa: S603 - fixed local helper
            [
                sys.executable,
                str(LISTEN_GUARD),
                "--pid",
                str(server.pid),
                "--port",
                str(port),
            ],
            check=False,
        )
        assert guard.returncode == 0
    finally:
        server.terminate()
        server.wait(timeout=5)

    wildcard = tmp_path / "wildcard.mjs"
    wildcard.write_text(
        "import net from 'node:net';\n"
        "net.createServer().listen(Number(process.env.TEST_PORT),'0.0.0.0');\n",
        encoding="utf-8",
    )
    refused = subprocess.run(  # noqa: S603 - fixed dedicated launcher and synthetic module
        ["node", str(EXPRESS_LOOPBACK), str(wildcard)],  # noqa: S607 - repository test runtime
        env={
            "PATH": os.environ["PATH"],
            "WISEACCT_PHASE7_EXPRESS_LOOPBACK": "1",
            "TEST_PORT": str(port),
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert refused.returncode != 0
    assert "refused a non-loopback listen host" in refused.stderr


def test_atomic_evidence_publish_refuses_collision_without_overwrite(tmp_path: Path) -> None:
    def bundle(path: Path) -> None:
        path.mkdir()
        (path / "express-before.txt").write_text("same", encoding="utf-8")
        (path / "express-after.txt").write_text("same", encoding="utf-8")
        (path / "result.status").write_text(
            "status=PASS\ncleanup=PASS\nexpressSnapshotUnchanged=true\n"
            "zeroCandidateResources=true\nprivateTempRemoved=true\n"
            "overallReplacementReady=false\n",
            encoding="utf-8",
        )
        (path / "provenance.txt").write_text("gitHead=synthetic\n", encoding="utf-8")
        for child in path.iterdir():
            child.chmod(0o400)
        path.chmod(0o500)

    final = tmp_path / "run"
    final.mkdir()
    (final / "marker").write_text("original", encoding="utf-8")
    staging = tmp_path / ".run.tmp.collision"
    bundle(staging)
    collision = subprocess.run(  # noqa: S603 - fixed local publisher
        [sys.executable, str(PUBLISH), "--staging", str(staging), "--final", str(final)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert collision.returncode == 2
    assert (final / "marker").read_text() == "original"
    assert (staging / "result.status").is_file()
    staging.chmod(0o700)
    for child in staging.iterdir():
        child.chmod(0o600)

    success_final = tmp_path / "fresh"
    success_staging = tmp_path / ".fresh.tmp.success"
    bundle(success_staging)
    success = subprocess.run(  # noqa: S603 - fixed local publisher
        [
            sys.executable,
            str(PUBLISH),
            "--staging",
            str(success_staging),
            "--final",
            str(success_final),
        ],
        check=False,
    )
    assert success.returncode == 0
    assert not success_staging.exists()
    assert (success_final / "result.status").is_file()
    success_final.chmod(0o700)
    for child in success_final.iterdir():
        child.chmod(0o600)


def test_atomic_evidence_publish_rejects_false_pass(tmp_path: Path) -> None:
    staging = tmp_path / ".run.tmp.false-pass"
    staging.mkdir()
    (staging / "express-before.txt").write_text("before", encoding="utf-8")
    (staging / "express-after.txt").write_text("after", encoding="utf-8")
    (staging / "result.status").write_text(
        "status=PASS\ncleanup=FAIL\nexpressSnapshotUnchanged=false\n"
        "zeroCandidateResources=unknown\nprivateTempRemoved=false\n"
        "overallReplacementReady=false\n",
        encoding="utf-8",
    )
    (staging / "provenance.txt").write_text("gitHead=synthetic\n", encoding="utf-8")
    for child in staging.iterdir():
        child.chmod(0o400)
    staging.chmod(0o500)
    result = subprocess.run(  # noqa: S603 - fixed local publisher
        [
            sys.executable,
            str(PUBLISH),
            "--staging",
            str(staging),
            "--final",
            str(tmp_path / "run"),
        ],
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "run").exists()
    staging.chmod(0o700)
    for child in staging.iterdir():
        child.chmod(0o600)


def test_terminate_runtime_kills_and_reaps_an_exact_child(tmp_path: Path) -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    function = source[source.index("terminate_runtime() {") : source.index("publish_evidence() {")]
    ready = tmp_path / "ready"
    script = tmp_path / "terminate.sh"
    script.write_text(
        "#!/usr/bin/env bash\nset -u\n"
        + function
        + "\n"
        + 'python3 -c "import pathlib,signal,time; '
        + "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        + f"pathlib.Path('{ready}').touch(); time.sleep(30)\" &\n"
        + "pid=$!\n"
        + f"for unused in {{1..100}}; do [[ -e '{ready}' ]] && break; sleep 0.01; done\n"
        + 'terminate_runtime "${pid}" || exit 20\n'
        + 'kill -0 "${pid}" 2>/dev/null && exit 21\n'
        + "if jobs -p | grep -q .; then exit 22; fi\n"
        + "exit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    started = time.monotonic()
    result = subprocess.run(  # noqa: S603 - synthetic child lifecycle harness
        [str(script)], check=False, capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr
    assert time.monotonic() - started >= 1.5


def test_private_temp_removal_is_verified_and_gates_pass_evidence(tmp_path: Path) -> None:
    private_root = Path("/tmp")  # noqa: S108 - exact helper contract under test
    private = private_root / f"wiseacct-phase7-runtime.pytest-{os.getpid()}"
    private.mkdir(mode=0o700, exist_ok=False)
    (private / "credential.json").write_text("secret", encoding="utf-8")
    removed = subprocess.run(  # noqa: S603 - fixed local removal helper
        [sys.executable, str(PRIVATE_REMOVE), "--path", str(private)], check=False
    )
    assert removed.returncode == 0
    assert not private.exists()

    outside = tmp_path / "wiseacct-phase7-runtime.invalid"
    outside.mkdir()
    refused = subprocess.run(  # noqa: S603 - fixed local removal helper
        [sys.executable, str(PRIVATE_REMOVE), "--path", str(outside)], check=False
    )
    assert refused.returncode == 1
    assert outside.exists()

    source = LAUNCHER.read_text(encoding="utf-8")
    cleanup = source[source.index("cleanup() {") : source.index("trap cleanup EXIT")]
    remove_position = cleanup.index('runtime_private_remove.py" --path "${PRIVATE_DIR}"')
    status_position = cleanup.index("final_status=FAIL")
    publish_position = cleanup.index('publish_evidence "${final_status}"')
    assert remove_position < status_position < publish_position
    assert 'private_temp_removed="false"' in cleanup
    assert "cleanup_status=1" in cleanup[remove_position:status_position]
    assert 'runtime_express_loopback.mjs"' in source
    assert "node dist/src/server.js" not in source
