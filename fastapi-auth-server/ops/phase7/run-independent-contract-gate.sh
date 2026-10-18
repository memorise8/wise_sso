#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( $# != 6 )); then
  echo "usage: run-independent-contract-gate.sh BASELINE_URL CANDIDATE_URL EXPRESS_CONFIG FASTAPI_CONFIG EVIDENCE_DIR PUBLIC_SCENARIOS" >&2
  exit 2
fi

readonly BASELINE_URL="$1" CANDIDATE_URL="$2" EXPRESS_CONFIG="$3" FASTAPI_CONFIG="$4" EVIDENCE_DIR="$5"
readonly PUBLIC_SCENARIOS="$6"
readonly PHASE7_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${PHASE7_DIR}/../.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly CONTRACTS_DIR="${REPO_DIR}/contracts"
readonly RUN_ID="$(basename -- "${EVIDENCE_DIR}")"
readonly SOURCE_REVISION="$(git -C "${REPO_DIR}" rev-parse --verify HEAD)"
readonly EXPRESS_ADAPTER="${CONTRACTS_DIR}/adapters/express_fixture.py"
readonly FASTAPI_ADAPTER="${CONTRACTS_DIR}/adapters/fastapi_fixture.py"
readonly EXPRESS_CONFIG_SHA256="$(sha256sum "${EXPRESS_CONFIG}" | cut -d' ' -f1)"
readonly FASTAPI_CONFIG_SHA256="$(sha256sum "${FASTAPI_CONFIG}" | cut -d' ' -f1)"
readonly PUBLIC_SCENARIOS_SHA256="$(sha256sum "${PUBLIC_SCENARIOS}" | cut -d' ' -f1)"

inputs_are_stable() {
  [[ "$(sha256sum "${EXPRESS_CONFIG}" | cut -d' ' -f1)" == "${EXPRESS_CONFIG_SHA256}" ]] \
    && [[ "$(sha256sum "${FASTAPI_CONFIG}" | cut -d' ' -f1)" == "${FASTAPI_CONFIG_SHA256}" ]] \
    && [[ "$(sha256sum "${PUBLIC_SCENARIOS}" | cut -d' ' -f1)" == "${PUBLIC_SCENARIOS_SHA256}" ]]
}

write_status() {
  local suite="$1" status="$2"
  shift 2
  {
    printf 'gate=independent-contract\nsuite=%s\nstatus=%s\n' "${suite}" "${status}"
    while (( $# )); do printf '%s\n' "$1"; shift; done
  } >"${EVIDENCE_DIR}/${suite}.status"
}

for suite in public guards fixtures; do write_status "${suite}" NOT_RUN; done
printf 'gate=independent-contract\nscope=independent-stateful\nstatus=RUNNING\n' \
  >"${EVIDENCE_DIR}/independent-contract.status"

printf 'gate=adapter-preflight\nstatus=RUNNING\n' >"${EVIDENCE_DIR}/adapter-preflight.status"
if ! inputs_are_stable; then
  printf 'gate=adapter-preflight\nstatus=FAIL\nreason=config-snapshot-instability\n' \
    >"${EVIDENCE_DIR}/adapter-preflight.status"
  exit 5
fi
if python3 "${PHASE7_DIR}/run_adapter_preflights.py" \
  --baseline "${BASELINE_URL}" --candidate "${CANDIDATE_URL}" \
  --express-adapter "${EXPRESS_ADAPTER}" --fastapi-adapter "${FASTAPI_ADAPTER}" \
  --express-config "${EXPRESS_CONFIG}" --fastapi-config "${FASTAPI_CONFIG}" \
  --output "${EVIDENCE_DIR}/adapter-preflight-results.jsonl"; then
  preflight_hash="$(sha256sum "${EVIDENCE_DIR}/adapter-preflight-results.jsonl" | cut -d' ' -f1)"
  printf 'gate=adapter-preflight\nstatus=PASS\nruntimeCount=2\njsonlSha256=%s\n' \
    "${preflight_hash}" >"${EVIDENCE_DIR}/adapter-preflight.status"
else
  preflight_status=$?
  preflight_hash="$(sha256sum "${EVIDENCE_DIR}/adapter-preflight-results.jsonl" | cut -d' ' -f1)"
  printf 'gate=adapter-preflight\nstatus=FAIL\nruntimeCount=2\njsonlSha256=%s\n' \
    "${preflight_hash}" >"${EVIDENCE_DIR}/adapter-preflight.status"
  printf 'gate=independent-contract\nscope=independent-stateful\nstatus=FAIL\nfailedSuite=adapter-preflight\n' \
    >"${EVIDENCE_DIR}/independent-contract.status"
  exit "${preflight_status}"
fi
if ! inputs_are_stable; then
  printf 'gate=independent-contract\nscope=independent-stateful\nstatus=FAIL\nfailedSuite=config-snapshot-stability\n' \
    >"${EVIDENCE_DIR}/independent-contract.status"
  exit 5
fi

for suite in public guards fixtures; do
  if ! inputs_are_stable; then
    printf 'gate=independent-contract\nscope=independent-stateful\nstatus=FAIL\nfailedSuite=config-snapshot-stability\n' \
      >"${EVIDENCE_DIR}/independent-contract.status"
    exit 5
  fi
  scenarios="${CONTRACTS_DIR}/scenarios/${suite}.json"
  if [[ "${suite}" == public ]]; then scenarios="${PUBLIC_SCENARIOS}"; fi
  output="${EVIDENCE_DIR}/${suite}-contract-results.jsonl"
  scenario_hash="$(sha256sum "${scenarios}" | cut -d' ' -f1)"
  scenario_count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1], encoding="utf-8"))["scenarios"]))' "${scenarios}")"
  write_status "${suite}" RUNNING "scenarioSha256=${scenario_hash}" "scenarioCount=${scenario_count}"
  if env -i PATH="${PATH}" PYTHONDONTWRITEBYTECODE=1 \
    python3 "${CONTRACTS_DIR}/bin/differential.py" \
      --baseline "${BASELINE_URL}" --candidate "${CANDIDATE_URL}" \
      --scenarios "${scenarios}" \
      --baseline-adapter "${EXPRESS_ADAPTER}" --candidate-adapter "${FASTAPI_ADAPTER}" \
      --baseline-adapter-config "${EXPRESS_CONFIG}" --candidate-adapter-config "${FASTAPI_CONFIG}" \
      --jsonl "${output}" \
      --provenance "runId=${RUN_ID}" --provenance "scenarioHash=${scenario_hash}" \
      --provenance "sourceRevision=${SOURCE_REVISION}" --provenance "topology=independent-stateful" \
      >"${EVIDENCE_DIR}/${suite}.stdout" 2>"${EVIDENCE_DIR}/${suite}.stderr"; then
    status=0
  else
    status=$?
  fi
  if ! inputs_are_stable; then status=5; fi
  if [[ -f "${output}" ]]; then
    result_hash="$(sha256sum "${output}" | cut -d' ' -f1)"
    result_count="$(wc -l <"${output}" | tr -d ' ')"
  else
    result_hash=absent
    result_count=0
  fi
  if (( status == 0 )) && [[ "${result_count}" != "${scenario_count}" ]]; then
    status=6
  fi
  if (( status != 0 )); then
    write_status "${suite}" FAIL "exitCode=${status}" "scenarioSha256=${scenario_hash}" \
      "scenarioCount=${scenario_count}" "jsonlSha256=${result_hash}" "resultCount=${result_count}"
    printf 'gate=independent-contract\nscope=independent-stateful\nstatus=FAIL\nfailedSuite=%s\n' \
      "${suite}" >"${EVIDENCE_DIR}/independent-contract.status"
    exit "${status}"
  fi
  write_status "${suite}" PASS "scenarioSha256=${scenario_hash}" \
    "scenarioCount=${scenario_count}" "jsonlSha256=${result_hash}" "resultCount=${result_count}"
done

printf 'gate=independent-contract\nscope=independent-stateful\nstatus=PASS\nsuiteOrder=public,guards,fixtures\n' \
  >"${EVIDENCE_DIR}/independent-contract.status"
