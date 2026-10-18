import json
import shutil
import subprocess
from pathlib import Path

import pytest

from wiseacct_sso.ops.audit_cleanup import coerce_positive_js_integer

ROOT = Path(__file__).parents[2]
EXPRESS_ROOT = ROOT.parent / "auth-server"


@pytest.mark.parametrize(
    "value",
    ["1", "1.0", "1e2", "0x10", "0b11", "0o10", " 45 ", "0", "-1", "1.5", ""],
)
def test_retention_coercion_matches_express_zod_oracle(value: str) -> None:
    node = shutil.which("node")
    if node is None or not (EXPRESS_ROOT / "node_modules" / "zod").is_dir():
        pytest.skip("Express Zod oracle is unavailable")
    script = """
import { z } from 'zod';
const value = JSON.parse(process.argv[1]);
try {
  console.log(JSON.stringify({ ok: true, value: z.coerce.number().int().positive().parse(value) }));
} catch {
  console.log(JSON.stringify({ ok: false }));
}
"""
    completed = subprocess.run(  # noqa: S603 - fixed local Node oracle, no shell
        [node, "--input-type=module", "-e", script, json.dumps(value)],
        cwd=EXPRESS_ROOT,
        capture_output=True,
        check=True,
        text=True,
    )
    oracle = json.loads(completed.stdout)

    if oracle["ok"]:
        assert coerce_positive_js_integer(value) == oracle["value"]
    else:
        with pytest.raises(ValueError):
            coerce_positive_js_integer(value)
