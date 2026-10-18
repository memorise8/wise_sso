#!/usr/bin/env python3
"""Remove and verify one exact Phase 7 private runtime directory."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

PREFIX = "wiseacct-phase7-runtime."
PRIVATE_ROOT = Path("/tmp")  # noqa: S108 - launcher creates one exact guarded mktemp here


def remove_private(path: Path) -> bool:
    if not path.is_absolute() or path.parent != PRIVATE_ROOT or not path.name.startswith(PREFIX):
        return False
    if path.is_symlink() or not path.is_dir():
        return False
    try:
        shutil.rmtree(path)
    except OSError:
        return False
    return not path.exists() and not path.is_symlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, required=True)
    args = parser.parse_args()
    return 0 if remove_private(args.path) else 1


if __name__ == "__main__":
    raise SystemExit(main())
