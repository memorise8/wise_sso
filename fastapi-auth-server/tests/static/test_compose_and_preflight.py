import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[2]
LAUNCHER = ROOT / "ops/dev-compose.sh"
VALIDATOR = ROOT / "ops/validate_dev_compose.py"


def run_launcher(
    env_file: Path,
    *,
    ambient: dict[str, str] | None = None,
    action: str = "--check-only",
) -> subprocess.CompletedProcess[str]:
    environment = {"PATH": os.environ["PATH"]}
    if ambient:
        environment.update(ambient)
    return subprocess.run(  # noqa: S603 - fixed local launcher with argument-vector execution
        [str(LAUNCHER), action, str(env_file)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )


def test_guarded_launcher_validates_exact_resolved_compose() -> None:
    result = run_launcher(ROOT / ".env.example")

    assert result.returncode == 0, result.stderr
    assert "no resources were created" in result.stdout


@pytest.mark.parametrize(
    "unsafe_line",
    [
        "NODE_ENV=production",
        "PORT=4000",
        "REDIS_URL=redis://127.0.0.1:6379/0",
        "JWT_REFRESH_SECRET=real-looking-value-without-marker",
        "DATABASE_URL=postgresql://user:pass@auth-server-app-1:5432/auth_db",
    ],
)
def test_launcher_rejects_current_or_non_synthetic_targets(
    tmp_path: Path,
    unsafe_line: str,
) -> None:
    contents = (ROOT / ".env.example").read_text()
    key = unsafe_line.split("=", 1)[0]
    replaced = "\n".join(
        unsafe_line if line.startswith(f"{key}=") else line for line in contents.splitlines()
    )
    env_file = tmp_path / "unsafe.fastapi-dev.env"
    env_file.write_text(replaced + "\n")

    result = run_launcher(env_file)
    assert result.returncode != 0


def test_launcher_rejects_ambient_compose_override() -> None:
    result = run_launcher(
        ROOT / ".env.example",
        ambient={"COMPOSE_PROJECT_NAME": "wiseacct_sso"},
    )

    assert result.returncode != 0
    assert "clear ambient" in result.stderr


def test_launcher_rejects_a_different_valid_rsa_private_key(tmp_path: Path) -> None:
    private_key = tmp_path / "other-private-key.pem"
    openssl = shutil.which("openssl")
    assert openssl is not None
    generated = subprocess.run(  # noqa: S603 - fixed OpenSSL argument vector
        [
            openssl,
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(private_key),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert generated.returncode == 0, generated.stderr
    replacement = private_key.read_text().strip().replace("\n", "\\n")
    contents = (ROOT / ".env.example").read_text()
    replaced = "\n".join(
        f'JWT_ACCESS_PRIVATE_KEY="{replacement}"'
        if line.startswith("JWT_ACCESS_PRIVATE_KEY=")
        else line
        for line in contents.splitlines()
    )
    env_file = tmp_path / "other-key.fastapi-dev.env"
    env_file.write_text(replaced + "\n")

    result = run_launcher(env_file)
    assert result.returncode != 0
    assert "pinned synthetic fixture" in result.stderr


def test_runtime_validator_rejects_an_image_declared_anonymous_volume(tmp_path: Path) -> None:
    manifest_path = ROOT / "ops/expected-resources.json"
    manifest = json.loads(manifest_path.read_text())
    containers: list[dict[str, Any]] = []
    for service in manifest["services"].values():
        ports: dict[str, list[dict[str, str]]] = {}
        for binding in service["hostBindings"]:
            host_ip, host_port, target = binding.split(":", 2)
            target_port, protocol = target.split("/", 1)
            ports[f"{target_port}/{protocol}"] = [{"HostIp": host_ip, "HostPort": host_port}]
        mounts = []
        for mount in service["mounts"]:
            if mount["type"] == "tmpfs":
                continue
            runtime_mount = {
                "Type": mount["type"],
                "Destination": mount["target"],
            }
            if mount["type"] == "volume":
                runtime_mount["Name"] = manifest["volumes"][mount["source"]]
            mounts.append(runtime_mount)
        containers.append(
            {
                "Name": f"/{service['containerName']}",
                "Mounts": mounts,
                "HostConfig": {
                    "Tmpfs": {
                        mount["target"]: "rw,noexec,nosuid,size=67108864"
                        for mount in service["mounts"]
                        if mount["type"] == "tmpfs"
                    }
                },
                "NetworkSettings": {
                    "Ports": ports,
                    "Networks": {
                        manifest["networks"][network]: {} for network in service["networks"]
                    },
                },
            }
        )
    inspect_file = tmp_path / "inspect.json"
    inspect_file.write_text(json.dumps(containers))
    container_names = tmp_path / "containers.txt"
    network_names = tmp_path / "networks.txt"
    volume_names = tmp_path / "volumes.txt"
    container_names.write_text(
        "\n".join(service["containerName"] for service in manifest["services"].values()) + "\n"
    )
    network_names.write_text("\n".join(manifest["networks"].values()) + "\n")
    volume_names.write_text("\n".join(manifest["volumes"].values()) + "\n")
    validator_arguments = [
        sys.executable,
        str(VALIDATOR),
        "runtime",
        str(inspect_file),
        str(container_names),
        str(network_names),
        str(volume_names),
        str(manifest_path),
    ]
    accepted = subprocess.run(  # noqa: S603 - fixed local validator
        validator_arguments,
        capture_output=True,
        check=False,
        text=True,
    )
    assert accepted.returncode == 0, accepted.stderr

    redis = next(
        container
        for container in containers
        if container["Name"] == "/wiseacct-sso-fastapi-dev-redis"
    )
    redis["Mounts"].append(
        {
            "Type": "volume",
            "Name": "unexpected-anonymous-volume",
            "Destination": "/unexpected",
        }
    )
    inspect_file.write_text(json.dumps(containers))
    rejected = subprocess.run(  # noqa: S603 - fixed local validator
        validator_arguments,
        capture_output=True,
        check=False,
        text=True,
    )
    assert rejected.returncode != 0
    assert "runtime resources differ" in rejected.stderr

    for names_file, unexpected, error_fragment in (
        (container_names, "unexpected-container", "container names"),
        (network_names, "unexpected-network", "network names"),
        (volume_names, "unexpected-volume", "volume names"),
    ):
        original = names_file.read_text()
        names_file.write_text(original + unexpected + "\n")
        extra_resource = subprocess.run(  # noqa: S603 - fixed local validator
            validator_arguments,
            capture_output=True,
            check=False,
            text=True,
        )
        names_file.write_text(original)
        assert extra_resource.returncode != 0
        assert error_fragment in extra_resource.stderr


def test_guarded_down_removes_project_volumes() -> None:
    launcher = LAUNCHER.read_text()
    assert "down --volumes --remove-orphans" in launcher


def test_partial_compose_up_failure_runs_scoped_cleanup(tmp_path: Path) -> None:
    real_config = subprocess.run(  # noqa: S603 - fixed Docker argument vector
        [
            "/usr/bin/docker",
            "compose",
            "--env-file",
            str(ROOT / ".env.example"),
            "-f",
            str(ROOT / "docker-compose.dev.yml"),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env={
            "PATH": os.environ["PATH"],
            "WISEACCT_FASTAPI_DEV_ENV_FILE": str(ROOT / ".env.example"),
        },
        capture_output=True,
        check=False,
        text=True,
    )
    assert real_config.returncode == 0, real_config.stderr
    config_file = tmp_path / "resolved.json"
    config_file.write_text(real_config.stdout)
    calls_file = tmp_path / "calls.txt"
    fake_docker = tmp_path / "docker"
    fake_docker.write_text(
        "#!/bin/sh\n"
        f"calls_file='{calls_file}'\n"
        f"config_file='{config_file}'\n"
        'case " $* " in\n'
        '  *" config --format json "*) cat "$config_file"; exit 0 ;;\n'
        '  *" up --build --detach --wait --wait-timeout 60 "*) echo up >>"$calls_file"; exit 1 ;;\n'
        '  *" down --volumes --remove-orphans "*) echo down >>"$calls_file"; exit 0 ;;\n'
        "esac\n"
        "exit 9\n"
    )
    fake_docker.chmod(0o700)

    result = run_launcher(
        ROOT / ".env.example",
        ambient={"PATH": f"{tmp_path}:{os.environ['PATH']}"},
        action="up",
    )

    assert result.returncode == 4
    assert calls_file.read_text().splitlines() == ["up", "down"]
