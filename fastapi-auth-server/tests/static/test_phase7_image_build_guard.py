import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "ops" / "phase7" / "build-exact-image.sh"
DOCKERFILE = ROOT / "Dockerfile"
FAKE_DOCKER = ROOT / "tests" / "helpers" / "fake_phase7_docker.py"
GIT = shutil.which("git") or "/usr/bin/git"
TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def git(arguments: list[str], cwd: Path, *, capture: bool = False) -> str:
    result = subprocess.run(  # noqa: S603 - fixed Git executable and synthetic repository
        [GIT, *arguments],
        cwd=cwd,
        check=True,
        capture_output=capture,
        text=True,
    )
    return (result.stdout or "").strip()


def make_repository(tmp_path: Path, *, mutable_base: bool = False) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    app = repository / "fastapi-auth-server"
    (app / "ops" / "phase7").mkdir(parents=True)
    script = app / "ops" / "phase7" / SCRIPT.name
    shutil.copy2(SCRIPT, script)
    script.chmod(0o755)
    for name in ("pyproject.toml", "uv.lock", "README.md"):
        shutil.copy2(ROOT / name, app / name)
    shutil.copytree(ROOT / "src", app / "src")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    if mutable_base:
        dockerfile = dockerfile.replace(
            "python:3.12.14-slim-bookworm@sha256:"
            "0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579",
            "python:3.12.14-slim-bookworm",
        )
    (app / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    git(["init", "-q"], repository)
    git(["config", "user.email", "phase7@example.invalid"], repository)
    git(["config", "user.name", "Phase 7"], repository)
    git(["add", "."], repository)
    git(["commit", "-qm", "synthetic exact image source"], repository)
    revision = git(["rev-parse", "HEAD"], repository, capture=True)
    return script, revision


def make_linked_repository(tmp_path: Path) -> tuple[Path, Path, str]:
    primary = tmp_path / "primary"
    primary.mkdir()
    primary_script, revision = make_repository(primary)
    primary_repository = primary_script.parents[3]
    linked = tmp_path / "linked"
    other = tmp_path / "other"
    git(["worktree", "add", "-q", "-b", "linked-test", str(linked)], primary_repository)
    git(["worktree", "add", "-q", "-b", "other-test", str(other)], primary_repository)
    return linked / "fastapi-auth-server" / "ops" / "phase7" / SCRIPT.name, other, revision


def environment(**overrides: str) -> dict[str, str]:
    return {"PATH": TRUSTED_PATH, **overrides}


def run_guard(
    script: Path,
    revision: str,
    env: dict[str, str],
    *,
    build: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - isolated committed script under test
        [str(script), "--build" if build else "--check-only", revision],
        cwd=script.parents[3],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def install_fake_docker(tmp_path: Path) -> tuple[Path, Path]:
    fake_bin = tmp_path / "attacker-bin"
    fake_bin.mkdir()
    fake = fake_bin / "docker"
    shutil.copy2(FAKE_DOCKER, fake)
    fake.chmod(0o755)
    return fake_bin, fake_bin / "docker-invoked"


def test_dockerfile_preserves_exact_image_provenance_labels() -> None:
    source = DOCKERFILE.read_text(encoding="utf-8")
    for argument in (
        "SOURCE_REVISION",
        "SOURCE_INPUTS_SHA256",
        "BUILD_MATERIALS_SHA256",
        "BASE_IMAGE_DIGEST",
    ):
        assert f"ARG {argument}" in source
    for label in (
        "org.opencontainers.image.revision",
        "com.wiseacct.sso.source-inputs-sha256",
        "com.wiseacct.sso.build-materials-sha256",
        "org.opencontainers.image.base.digest",
    ):
        assert label in source


def test_guard_bootstraps_every_external_tool_under_a_cleared_environment() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'exec /usr/bin/env -i PATH="${TRUSTED_PATH_BOOTSTRAP}" LC_ALL=C' in source
    assert "WISEACCT_PHASE7_SANITIZED_ENV=1 /usr/bin/bash" in source
    assert "TAR_OPTIONS" in source


def test_check_only_hashes_pinned_inputs_without_claiming_docker_trust(tmp_path: Path) -> None:
    script, revision = make_repository(tmp_path)
    result = run_guard(script, revision, environment())
    assert result.returncode == 0, result.stderr
    listing = subprocess.run(  # noqa: S603 - fixed Git and synthetic repository
        [
            GIT,
            "ls-tree",
            "-r",
            revision,
            "--",
            "fastapi-auth-server/Dockerfile",
            "fastapi-auth-server/pyproject.toml",
            "fastapi-auth-server/uv.lock",
            "fastapi-auth-server/README.md",
            "fastapi-auth-server/src",
        ],
        cwd=script.parents[3],
        check=True,
        capture_output=True,
    ).stdout
    assert f"source_inputs_sha256={hashlib.sha256(listing).hexdigest()}" in result.stdout
    assert "docker_trust=NOT_CHECKED" in result.stdout


def test_build_is_unconditionally_incomplete_without_invoking_docker(tmp_path: Path) -> None:
    script, revision = make_repository(tmp_path)
    fake_bin, invoked = install_fake_docker(tmp_path)
    result = run_guard(script, revision, {"PATH": f"{fake_bin}:{TRUSTED_PATH}"}, build=True)
    assert result.returncode != 0
    assert "PATH tool substitution" in result.stderr
    assert not invoked.exists()

    result = run_guard(script, revision, environment(), build=True)
    assert result.returncode != 0
    assert "CONTROLLED_TOOLCHAIN_REQUIRED" in result.stderr
    assert "phase7-image-build result=PASS" not in result.stdout
    assert not invoked.exists()


def test_tar_checkpoint_action_is_rejected_without_execution(tmp_path: Path) -> None:
    script, revision = make_repository(tmp_path)
    marker = tmp_path / "checkpoint-action-executed"
    exact_attack = f"--checkpoint=1 --checkpoint-action=exec=/usr/bin/touch {marker}"
    result = run_guard(script, revision, environment(TAR_OPTIONS=exact_attack))
    assert result.returncode != 0
    assert "external-tool option variable is forbidden: TAR_OPTIONS" in result.stderr
    assert not marker.exists()


def test_bash_env_payload_cannot_run_before_environment_sanitization(tmp_path: Path) -> None:
    script, revision = make_repository(tmp_path)
    marker = tmp_path / "bash-env-executed"
    payload = tmp_path / "bash-env-payload.sh"
    payload.write_text(f"/usr/bin/touch {marker}\n", encoding="utf-8")
    result = run_guard(script, revision, environment(BASH_ENV=str(payload)))
    assert result.returncode != 0
    assert "external-tool option variable is forbidden: BASH_ENV" in result.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    "variable",
    ["GREP_OPTIONS", "AWKPATH", "POSIXLY_CORRECT", "GZIP", "XZ_OPT", "TMPDIR", "BASH_ENV"],
)
def test_guard_rejects_other_external_tool_environment_injection(
    tmp_path: Path, variable: str
) -> None:
    script, revision = make_repository(tmp_path)
    result = run_guard(script, revision, environment(**{variable: "attacker-value"}))
    assert result.returncode != 0
    assert f"external-tool option variable is forbidden: {variable}" in result.stderr


def test_check_only_accepts_safely_bound_linked_worktree(tmp_path: Path) -> None:
    script, _, revision = make_linked_repository(tmp_path)
    result = run_guard(script, revision, environment())
    assert result.returncode == 0, result.stderr


def test_guard_rejects_gitfile_redirected_to_another_worktree(tmp_path: Path) -> None:
    script, other, revision = make_linked_repository(tmp_path)
    other_gitdir = (other / ".git").read_text(encoding="utf-8").strip().removeprefix("gitdir: ")
    script.parents[3].joinpath(".git").write_text(f"gitdir: {other_gitdir}\n", encoding="utf-8")
    result = run_guard(script, revision, environment())
    assert result.returncode != 0
    assert "gitfile target" in result.stderr or "backlink" in result.stderr


@pytest.mark.parametrize(
    "variable",
    ["GIT_DIR", "GIT_INDEX_FILE", "GIT_CONFIG_COUNT", "GIT_OBJECT_DIRECTORY"],
)
def test_guard_rejects_all_ambient_git_routing_variables(tmp_path: Path, variable: str) -> None:
    script, revision = make_repository(tmp_path)
    result = run_guard(script, revision, environment(**{variable: str(tmp_path / "attacker")}))
    assert result.returncode != 0
    assert "ambient Git routing/configuration variables are forbidden" in result.stderr


@pytest.mark.parametrize("spelling", ["extensions.partialclone", "extensions.partialClone"])
def test_guard_rejects_case_normalized_common_partialclone(tmp_path: Path, spelling: str) -> None:
    script, revision = make_repository(tmp_path)
    git(["config", spelling, "origin"], script.parents[3])
    result = run_guard(script, revision, environment())
    assert result.returncode != 0
    assert "common Git config" in result.stderr


@pytest.mark.parametrize("directive", ["include.path", "includeIf.gitdir:/**.path"])
def test_guard_rejects_common_config_include_before_following_promisor_file(
    tmp_path: Path, directive: str
) -> None:
    script, revision = make_repository(tmp_path)
    included = tmp_path / "untrusted-common.config"
    included.write_text('[remote "attack"]\n\tpromisor = true\n', encoding="utf-8")
    git(["config", directive, str(included)], script.parents[3])
    result = run_guard(script, revision, environment())
    assert result.returncode != 0
    assert "include directives are forbidden in common Git config" in result.stderr


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("remote.attack.promisor", "true"),
        ("extensions.partialclone", "attack"),
        ("core.alternateRefsCommand", "/usr/bin/false"),
    ],
)
def test_linked_worktree_rejects_unsafe_worktree_scoped_object_config(
    tmp_path: Path, key: str, value: str
) -> None:
    script, _, revision = make_linked_repository(tmp_path)
    repository = script.parents[3]
    git(["config", "extensions.worktreeConfig", "true"], repository)
    git(["config", "--worktree", key, value], repository)
    result = run_guard(script, revision, environment())
    assert result.returncode != 0
    assert "worktree Git config" in result.stderr


@pytest.mark.parametrize(
    "included_body",
    [
        '[remote "attack"]\n\tpromisor = true\n',
        "[extensions]\n\tpartialClone = attack\n",
        "[core]\n\talternateRefsCommand = /usr/bin/false\n",
    ],
)
def test_linked_worktree_rejects_include_before_following_unsafe_object_config(
    tmp_path: Path, included_body: str
) -> None:
    script, _, revision = make_linked_repository(tmp_path)
    repository = script.parents[3]
    included = tmp_path / "untrusted-worktree.config"
    included.write_text(included_body, encoding="utf-8")
    git(["config", "extensions.worktreeConfig", "true"], repository)
    git(["config", "--worktree", "include.path", str(included)], repository)
    result = run_guard(script, revision, environment())
    assert result.returncode != 0
    assert "include directives are forbidden in worktree Git config" in result.stderr


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("wrong-head", "HEAD does not equal"),
        ("dirty", "entire repository must be clean"),
        ("mutable-base", "pinned by sha256 digest"),
    ],
)
def test_guard_fails_closed_on_source_violation(tmp_path: Path, case: str, message: str) -> None:
    script, revision = make_repository(tmp_path, mutable_base=case == "mutable-base")
    if case == "wrong-head":
        revision = "0" * 40
    elif case == "dirty":
        script.parents[3].joinpath("untracked-secret.txt").write_text(
            "must block", encoding="utf-8"
        )
    result = run_guard(script, revision, environment(), build=True)
    assert result.returncode != 0
    assert message in result.stderr
