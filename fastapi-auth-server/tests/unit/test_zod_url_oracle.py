import json
import shutil
import subprocess
from pathlib import Path

import pytest

from wiseacct_sso.api.routes.auth import _is_absolute_zod_url

ROOT = Path(__file__).parents[2]
ZOD_PACKAGE = ROOT.parent / "auth-server" / "node_modules" / "zod"
URL_ORACLE_CORPUS = (
    ("not-a-url", False),
    ("/relative", False),
    ("//x", False),
    ("https://", False),
    (" http://x ", True),
    ("http://x\n", True),
    ("http://x\v", True),
    ("HTTP://x", True),
    ("http:x", True),
    ("http:/x", True),
    ("http://.com", True),
    ("http://x..com", True),
    ("http://\ud800", False),
    ("foo:", True),
    ("foo:bar", True),
    ("foo://", True),
    ("foo:// space", False),
    ("file:", True),
    ("file:///", True),
)


@pytest.mark.parametrize(("value", "expected"), URL_ORACLE_CORPUS)
def test_bounded_url_predicate_matches_checked_in_zod_oracle(value: str, expected: bool) -> None:
    assert _is_absolute_zod_url(value) is expected


def test_checked_in_url_corpus_still_matches_installed_zod() -> None:
    node = shutil.which("node")
    if node is None or not ZOD_PACKAGE.exists():
        pytest.skip("Node or sibling auth-server Zod dependency is unavailable")
    script = """
const { z } = require(process.argv[1]);
const corpus = JSON.parse(process.argv[2]);
const results = corpus.map(([value]) => z.string().url().safeParse(value).success);
process.stdout.write(JSON.stringify(results));
"""
    completed = subprocess.run(  # noqa: S603 - fixed local Node binary and checked-in corpus
        [
            node,
            "-e",
            script,
            str(ZOD_PACKAGE),
            json.dumps(URL_ORACLE_CORPUS, ensure_ascii=True),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    observed = json.loads(completed.stdout)
    assert observed == [expected for _value, expected in URL_ORACLE_CORPUS]
