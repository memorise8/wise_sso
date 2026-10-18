#!/usr/bin/env python3
"""Execute one runtime with an exact private JSON environment."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit("usage: runtime_exec.py <0600-env.json> <command> [argument ...]")
    path = Path(sys.argv[1])
    if not path.is_file() or path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit("runtime environment must be a non-link regular 0600 file")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in document.items()
    ):
        raise SystemExit("runtime environment must be a string environment object")
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **document}
    os.execvpe(sys.argv[2], sys.argv[2:], environment)  # noqa: S606 - explicit argv, no shell
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
