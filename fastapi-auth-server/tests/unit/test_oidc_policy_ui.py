"""실제 정책 편집 JS의 표시·권한·응답 순서·XSS를 검증합니다."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize(
    "mode",
    [
        "record",
        "self",
        "approve",
        "reject",
        "viewer",
        "stale-success",
        "stale-error",
        "members-policy",
        "members-late-success",
        "members-late-error",
    ],
)
def test_oidc_policy_ui(mode: str) -> None:
    node = shutil.which("node")
    assert node is not None, "정책 화면 검사에는 Node.js가 필요합니다."
    result = subprocess.run(  # noqa: S603
        [
            node,
            str(ROOT / "tests/helpers/oidc_policy_ui_oracle.mjs"),
            str(ROOT / "src/wiseacct_sso/static/assets/admin-service.js"),
            mode,
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"mode": mode, "passed": True}
