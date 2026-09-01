#!/usr/bin/env python3
"""Validate the exact successful shared-state runner summary and JSONL."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

CONCURRENT_SCHEDULES = {
    "express-handoff-mixed-consume-race",
    "fastapi-handoff-mixed-consume-race",
    "mixed-refresh-race",
    "express-logout-fastapi-refresh-race",
    "fastapi-logout-express-refresh-race",
    "mixed-simultaneous-shared-rate-limit",
    "mixed-failed-login-race",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(summary_path: Path, jsonl_path: Path, scenarios_path: Path) -> None:
    summary = load_json(summary_path)
    expected_summary = {
        "suiteId": "shared-state-core-v1",
        "status": "PASS",
        "plannedTrials": 100,
        "passedTrials": 100,
        "failedTrials": 0,
        "notRunTrials": 0,
        "fullPhase7SampleSatisfied": False,
        "overallReplacementReady": False,
    }
    if summary != expected_summary:
        raise ValueError("runner summary is not the exact successful core result")
    manifest = load_json(scenarios_path)
    schedule_ids = [item["id"] for item in manifest["scenarios"]]
    if len(schedule_ids) != 10 or manifest.get("trialsPerSchedule") != 10:
        raise ValueError("shared-state manifest does not define the exact core sample")
    rows = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]
    if len(rows) != 100:
        raise ValueError("shared-state JSONL must contain exactly 100 rows")
    expected_trials = {
        (schedule_id, trial) for schedule_id in schedule_ids for trial in range(1, 11)
    }
    actual_trials = {(row.get("scheduleId"), row.get("trial")) for row in rows}
    if actual_trials != expected_trials:
        raise ValueError("shared-state JSONL does not cover each exact schedule trial")
    if any(
        row.get("suiteId") != "shared-state-core-v1"
        or row.get("outcome") != "PASS"
        or row.get("attempt") != 1
        or row.get("retryCount") != 0
        or row.get("fullPhase7SampleSatisfied") is not False
        or row.get("overallReplacementReady") is not False
        for row in rows
    ):
        raise ValueError("shared-state JSONL contains a non-PASS or retry record")
    overlap_count = 0
    for row in rows:
        evidence = row.get("evidence")
        overlap = (
            evidence.get("mixedRuntimeRequestLifetimeOverlap")
            if isinstance(evidence, dict)
            else None
        )
        if row["scheduleId"] in CONCURRENT_SCHEDULES:
            if overlap is not True:
                raise ValueError("concurrent schedule lacks mixed-runtime request overlap evidence")
            overlap_count += 1
        elif overlap not in {None, False}:
            raise ValueError("sequential schedule claimed mixed-runtime request overlap")
    if overlap_count != 70:
        raise ValueError("shared-state result must prove exactly 70 concurrent overlap trials")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--jsonl", type=Path, required=True)
    parser.add_argument("--scenarios", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate(args.summary, args.jsonl, args.scenarios)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"shared-state result validation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
