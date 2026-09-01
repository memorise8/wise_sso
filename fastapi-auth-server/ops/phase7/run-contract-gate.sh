#!/usr/bin/env bash
set -euo pipefail

if (( $# != 4 )); then
  echo "usage: run-contract-gate.sh BASELINE_URL CANDIDATE_URL SCENARIOS EVIDENCE_DIR" >&2
  exit 2
fi

readonly BASELINE_URL="$1"
readonly CANDIDATE_URL="$2"
readonly SCENARIOS="$3"
readonly EVIDENCE_DIR="$4"
readonly PHASE7_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${PHASE7_DIR}/../.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly RUN_ID="$(basename -- "${EVIDENCE_DIR}")"
readonly SOURCE_REVISION="$(git -C "${REPO_DIR}" rev-parse --verify HEAD)"
readonly SCENARIO_SHA256="$(sha256sum "${SCENARIOS}" | cut -d' ' -f1)"

{
  printf 'gate=public-contract\n'
  printf 'scope=public-only\n'
  printf 'fixtures=NOT_RUN\n'
  printf 'guards=NOT_RUN\n'
  printf 'status=RUNNING\n'
} >"${EVIDENCE_DIR}/contract.status"

if env -i \
  PATH="${PATH}" \
  PYTHONDONTWRITEBYTECODE=1 \
  python3 "${REPO_DIR}/contracts/bin/differential.py" \
    --baseline "${BASELINE_URL}" \
    --candidate "${CANDIDATE_URL}" \
    --scenarios "${SCENARIOS}" \
    --jsonl "${EVIDENCE_DIR}/public-contract-results.jsonl" \
    --provenance "runId=${RUN_ID}" \
    --provenance "scenarioHash=${SCENARIO_SHA256}" \
    --provenance "sourceRevision=${SOURCE_REVISION}" \
    --provenance "topology=public-only" \
    >"${EVIDENCE_DIR}/contract.stdout" \
    2>"${EVIDENCE_DIR}/contract.stderr"; then
  printf 'gate=public-contract\nscope=public-only\nfixtures=NOT_RUN\nguards=NOT_RUN\nstatus=PASS\n' \
    >"${EVIDENCE_DIR}/contract.status"
  exit 0
else
  status=$?
fi

printf 'gate=public-contract\nscope=public-only\nfixtures=NOT_RUN\nguards=NOT_RUN\nstatus=FAIL\nexitCode=%s\n' \
  "${status}" >"${EVIDENCE_DIR}/contract.status"
exit "${status}"
