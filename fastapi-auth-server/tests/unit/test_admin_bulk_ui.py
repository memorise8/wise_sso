"""Exercise the real dashboard JS without requiring a browser or network."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize("session_mode", [False, True])
def test_bulk_dashboard_selection_requests_and_escaped_rendering(session_mode: bool) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the dashboard DOM oracle")
    result = subprocess.run(  # noqa: S603 - fixed Node runtime and checked-in oracle
        [
            node,
            str(ROOT / "tests/helpers/admin_bulk_oracle.mjs"),
            str(ROOT / "src/wiseacct_sso/static/assets/admin-dashboard.js"),
            *(["--session"] if session_mode else []),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    checks = json.loads(result.stdout)
    assert len(checks) == 9
    assert all(checks.values())
