"""실제 권한 점검 JS의 KST·XSS·결정 동작을 검증합니다."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize("mode", ["viewer", "KEEP", "REVOKE", "conflict", "different-completer"])
def test_access_review_ui(mode: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("점검 화면 검사에는 Node.js가 필요합니다.")
    result = subprocess.run(  # noqa: S603
        [
            node,
            str(ROOT / "tests/helpers/access_review_ui_oracle.mjs"),
            str(ROOT / "src/wiseacct_sso/static/assets/admin-access-reviews.js"),
            mode,
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"mode": mode, "passed": True}
