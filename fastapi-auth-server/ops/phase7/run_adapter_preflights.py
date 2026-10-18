#!/usr/bin/env python3
"""Run both isolated adapter preflights and write sanitized evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

SAFE_RESULT_KEYS = {"status", "database", "redisDatabase", "runtime", "schema"}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--baseline", required=True)
    result.add_argument("--candidate", required=True)
    result.add_argument("--express-adapter", type=Path, required=True)
    result.add_argument("--fastapi-adapter", type=Path, required=True)
    result.add_argument("--express-config", type=Path, required=True)
    result.add_argument("--fastapi-config", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def run_one(runtime: str, adapter: Path, config: Path, origin: str) -> dict[str, Any]:
    document = json.loads(config.read_text(encoding="utf-8"))
    environment = {"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1", **document}
    environment["CONTRACT_BASE_URL"] = origin
    try:
        completed = subprocess.run(  # noqa: S603 - validated fixed adapter path from the gate
            [str(adapter), "preflight", runtime],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode == 0:
            raw = json.loads(completed.stdout)
            safe = {key: raw[key] for key in SAFE_RESULT_KEYS if key in raw}
            return {"runtime": runtime, "outcome": "pass", "evidence": safe}
        failure = completed.stderr or completed.stdout or f"exit {completed.returncode}"
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        failure = type(exc).__name__
    return {
        "runtime": runtime,
        "outcome": "fail",
        "errorSha256": hashlib.sha256(failure.encode("utf-8")).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    results = [
        run_one("express", args.express_adapter, args.express_config, args.baseline),
        run_one("fastapi", args.fastapi_adapter, args.fastapi_config, args.candidate),
    ]
    args.output.write_text(
        "".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n" for item in results),
        encoding="utf-8",
    )
    return 0 if all(item["outcome"] == "pass" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
