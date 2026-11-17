"""실제 대시보드 JS의 XSS 방어와 viewer 변경 버튼 제거를 검증합니다."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize("viewer", [False, True])
def test_dashboard_xss_and_viewer_controls(viewer: bool) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("화면 동작 검사에는 Node.js가 필요합니다.")

    result = subprocess.run(  # noqa: S603
        [
            node,
            str(ROOT / "tests/helpers/admin_dashboard_xss_oracle.mjs"),
            str(ROOT / "src/wiseacct_sso/static/assets/admin-dashboard.js"),
            *(["--viewer"] if viewer else []),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["executedGlobals"] == []

    forbidden_tags = {"SCRIPT", "IMG", "SVG", "IFRAME", "MATH"}
    for section in ("users", "audit"):
        assert forbidden_tags.isdisjoint(report[section]["tags"])

    assert any("<script>" in value for value in report["users"]["texts"])

    if viewer:
        mutation_keys = {
            "removeRole",
            "assignRole",
            "revoke",
            "userTypeSelect",
            "statusSelect",
            "selectUser",
        }
        for dataset in report["users"]["datasets"]:
            assert mutation_keys.isdisjoint(dataset)
        assert "BUTTON" not in report["users"]["tags"]
        assert "SELECT" not in report["users"]["tags"]
        assert "INPUT" not in report["users"]["tags"]
