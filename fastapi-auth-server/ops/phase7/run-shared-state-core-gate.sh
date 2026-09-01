#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( $# != 5 )); then
  echo "usage: run-shared-state-core-gate.sh EXPRESS_URL FASTAPI_URL EXPRESS_CONFIG FASTAPI_CONFIG EVIDENCE_DIR" >&2
  exit 2
fi

readonly EXPRESS_URL="$1" FASTAPI_URL="$2" EXPRESS_CONFIG="$3" FASTAPI_CONFIG="$4" EVIDENCE_DIR="$5"
readonly PHASE7_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${PHASE7_DIR}/../.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly CONTRACTS_DIR="${REPO_DIR}/contracts"
readonly SCENARIOS="${CONTRACTS_DIR}/scenarios/shared-state-core-v1.json"
readonly RUNNER="${CONTRACTS_DIR}/bin/shared_state.py"
readonly RESULT_VALIDATOR="${PHASE7_DIR}/validate_shared_result.py"
readonly EXPRESS_ADAPTER="${CONTRACTS_DIR}/adapters/express_fixture.py"
readonly FASTAPI_ADAPTER="${CONTRACTS_DIR}/adapters/fastapi_fixture.py"
readonly RUN_ID="$(basename -- "${EVIDENCE_DIR}")"
readonly SOURCE_REVISION="$(git -C "${REPO_DIR}" rev-parse --verify HEAD)"
readonly SOURCE_TREE="$(git -C "${REPO_DIR}" rev-parse --verify HEAD^{tree})"
readonly EVIDENCE_RELATIVE="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve().relative_to(pathlib.Path(sys.argv[2]).resolve()))' "${EVIDENCE_DIR}" "${REPO_DIR}" 2>/dev/null || true)"

tree_is_clean_except_evidence() {
  local untracked
  git -C "${REPO_DIR}" diff --quiet -- \
    && git -C "${REPO_DIR}" diff --cached --quiet -- \
    && [[ "$(git -C "${REPO_DIR}" rev-parse --verify HEAD)" == "${SOURCE_REVISION}" ]] \
    && [[ "$(git -C "${REPO_DIR}" rev-parse --verify HEAD^{tree})" == "${SOURCE_TREE}" ]] \
    || return 1
  while IFS= read -r -d '' untracked; do
    if [[ -z "${EVIDENCE_RELATIVE}" || "${untracked}" != "${EVIDENCE_RELATIVE}/"* ]]; then
      return 1
    fi
  done < <(git -C "${REPO_DIR}" ls-files --others --exclude-standard -z)
}

for required in "${SCENARIOS}" "${RUNNER}" "${RESULT_VALIDATOR}" "${EXPRESS_ADAPTER}" "${FASTAPI_ADAPTER}"; do
  [[ -f "${required}" && ! -L "${required}" ]] || {
    echo "shared-state gate input is missing or linked" >&2
    exit 2
  }
done
[[ -d "${EVIDENCE_DIR}" && ! -L "${EVIDENCE_DIR}" ]] || exit 2
tree_is_clean_except_evidence || {
  echo "shared-state gate requires a clean committed source tree" >&2
  exit 2
}

readonly PRIVATE_SNAPSHOTS="$(mktemp -d /tmp/wiseacct-phase7-shared-gate.XXXXXXXX)"
trap 'rm -rf -- "${PRIVATE_SNAPSHOTS}"' EXIT INT TERM
chmod 0700 "${PRIVATE_SNAPSHOTS}"

readonly EXPRESS_CONFIG_SHA256="$(sha256sum "${EXPRESS_CONFIG}" | cut -d' ' -f1)"
readonly FASTAPI_CONFIG_SHA256="$(sha256sum "${FASTAPI_CONFIG}" | cut -d' ' -f1)"
readonly SCENARIOS_SHA256="$(sha256sum "${SCENARIOS}" | cut -d' ' -f1)"
readonly RUNNER_SHA256="$(sha256sum "${RUNNER}" | cut -d' ' -f1)"
readonly RESULT_VALIDATOR_SHA256="$(sha256sum "${RESULT_VALIDATOR}" | cut -d' ' -f1)"
readonly EXPRESS_ADAPTER_SHA256="$(sha256sum "${EXPRESS_ADAPTER}" | cut -d' ' -f1)"
readonly FASTAPI_ADAPTER_SHA256="$(sha256sum "${FASTAPI_ADAPTER}" | cut -d' ' -f1)"

inputs_are_stable() {
  [[ "$(sha256sum "${EXPRESS_CONFIG}" | cut -d' ' -f1)" == "${EXPRESS_CONFIG_SHA256}" ]] \
    && [[ "$(sha256sum "${FASTAPI_CONFIG}" | cut -d' ' -f1)" == "${FASTAPI_CONFIG_SHA256}" ]] \
    && [[ "$(sha256sum "${SCENARIOS}" | cut -d' ' -f1)" == "${SCENARIOS_SHA256}" ]] \
    && [[ "$(sha256sum "${RUNNER}" | cut -d' ' -f1)" == "${RUNNER_SHA256}" ]] \
    && [[ "$(sha256sum "${RESULT_VALIDATOR}" | cut -d' ' -f1)" == "${RESULT_VALIDATOR_SHA256}" ]] \
    && [[ "$(sha256sum "${EXPRESS_ADAPTER}" | cut -d' ' -f1)" == "${EXPRESS_ADAPTER_SHA256}" ]] \
    && [[ "$(sha256sum "${FASTAPI_ADAPTER}" | cut -d' ' -f1)" == "${FASTAPI_ADAPTER_SHA256}" ]]
}

printf 'gate=shared-state-core-v1\nstatus=RUNNING\noverallReplacementReady=false\n' \
  >"${EVIDENCE_DIR}/shared-state.status"
printf 'gate=adapter-preflight\nstatus=NOT_RUN\n' \
  >"${EVIDENCE_DIR}/adapter-preflight.status"

if ! env -i PATH="${PATH}" PYTHONDONTWRITEBYTECODE=1 \
  WISEACCT_PHASE7_EXPRESS_DATABASE_URL="${WISEACCT_PHASE7_EXPRESS_DATABASE_URL:-}" \
  WISEACCT_PHASE7_FASTAPI_DATABASE_URL="${WISEACCT_PHASE7_FASTAPI_DATABASE_URL:-}" \
  WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL="${WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL:-}" \
  WISEACCT_PHASE7_EXPRESS_REDIS_URL="${WISEACCT_PHASE7_EXPRESS_REDIS_URL:-}" \
  WISEACCT_PHASE7_FASTAPI_REDIS_URL="${WISEACCT_PHASE7_FASTAPI_REDIS_URL:-}" \
  python3 "${PHASE7_DIR}/validate_shared_inputs.py" \
    --express "${EXPRESS_URL}" --fastapi "${FASTAPI_URL}" \
    --express-config "${EXPRESS_CONFIG}" --fastapi-config "${FASTAPI_CONFIG}" \
    --snapshot-dir "${PRIVATE_SNAPSHOTS}" --repo "${REPO_DIR}" --evidence "${EVIDENCE_DIR}" \
    >"${EVIDENCE_DIR}/topology.json"; then
  printf 'gate=shared-state-core-v1\nstatus=FAIL\nfailedSuite=input-validation\noverallReplacementReady=false\n' \
    >"${EVIDENCE_DIR}/shared-state.status"
  exit 2
fi

if ! inputs_are_stable; then
  printf 'gate=shared-state-core-v1\nstatus=FAIL\nfailedSuite=input-stability\noverallReplacementReady=false\n' \
    >"${EVIDENCE_DIR}/shared-state.status"
  exit 5
fi

printf 'gate=adapter-preflight\nstatus=RUNNING\n' \
  >"${EVIDENCE_DIR}/adapter-preflight.status"
if python3 "${PHASE7_DIR}/run_adapter_preflights.py" \
  --baseline "${EXPRESS_URL}" --candidate "${FASTAPI_URL}" \
  --express-adapter "${EXPRESS_ADAPTER}" --fastapi-adapter "${FASTAPI_ADAPTER}" \
  --express-config "${PRIVATE_SNAPSHOTS}/express.json" \
  --fastapi-config "${PRIVATE_SNAPSHOTS}/fastapi.json" \
  --output "${EVIDENCE_DIR}/adapter-preflight-results.jsonl"; then
  preflight_status=0
else
  preflight_status=$?
fi
readonly PREFLIGHT_HASH="$(sha256sum "${EVIDENCE_DIR}/adapter-preflight-results.jsonl" | cut -d' ' -f1)"
if (( preflight_status != 0 )); then
  printf 'gate=adapter-preflight\nstatus=FAIL\nruntimeCount=2\njsonlSha256=%s\n' \
    "${PREFLIGHT_HASH}" >"${EVIDENCE_DIR}/adapter-preflight.status"
  printf 'gate=shared-state-core-v1\nstatus=FAIL\nfailedSuite=adapter-preflight\noverallReplacementReady=false\n' \
    >"${EVIDENCE_DIR}/shared-state.status"
  exit "${preflight_status}"
fi
printf 'gate=adapter-preflight\nstatus=PASS\nruntimeCount=2\njsonlSha256=%s\n' \
  "${PREFLIGHT_HASH}" >"${EVIDENCE_DIR}/adapter-preflight.status"

if ! inputs_are_stable; then
  printf 'gate=shared-state-core-v1\nstatus=FAIL\nfailedSuite=input-stability\noverallReplacementReady=false\n' \
    >"${EVIDENCE_DIR}/shared-state.status"
  exit 5
fi

readonly OUTPUT="${EVIDENCE_DIR}/shared-state-results.jsonl"
if env -i PATH="${PATH}" PYTHONDONTWRITEBYTECODE=1 \
  python3 "${RUNNER}" \
    --express "${EXPRESS_URL}" --fastapi "${FASTAPI_URL}" \
    --scenarios "${SCENARIOS}" \
    --fixture-adapter "${EXPRESS_ADAPTER}" \
    --fixture-config "${PRIVATE_SNAPSHOTS}/express.json" \
    --jsonl "${OUTPUT}" --run-id "${RUN_ID}" --source-revision "${SOURCE_REVISION}" \
    >"${EVIDENCE_DIR}/shared-state.stdout" 2>"${EVIDENCE_DIR}/shared-state.stderr"; then
  runner_status=0
else
  runner_status=$?
fi
if ! inputs_are_stable || ! tree_is_clean_except_evidence; then runner_status=5; fi
if [[ -f "${OUTPUT}" ]]; then
  result_count="$(wc -l <"${OUTPUT}" | tr -d ' ')"
  result_hash="$(sha256sum "${OUTPUT}" | cut -d' ' -f1)"
else
  result_count=0
  result_hash=absent
fi
if (( runner_status == 0 )) && ! python3 "${RESULT_VALIDATOR}" \
  --summary "${EVIDENCE_DIR}/shared-state.stdout" --jsonl "${OUTPUT}" \
  --scenarios "${SCENARIOS}"; then
  runner_status=6
fi
if (( runner_status != 0 )); then
  printf 'gate=shared-state-core-v1\nstatus=FAIL\nexitCode=%s\nresultCount=%s\njsonlSha256=%s\noverallReplacementReady=false\n' \
    "${runner_status}" "${result_count}" "${result_hash}" \
    >"${EVIDENCE_DIR}/shared-state.status"
  exit "${runner_status}"
fi
if ! inputs_are_stable || ! tree_is_clean_except_evidence; then
  printf 'gate=shared-state-core-v1\nstatus=FAIL\nfailedSuite=source-stability\noverallReplacementReady=false\n' \
    >"${EVIDENCE_DIR}/shared-state.status"
  exit 5
fi

printf 'gate=shared-state-core-v1\nstatus=PASS\nresultCount=100\nconcurrentTrialCount=70\nmixedRuntimeOverlapCount=70\noverlapMismatchCount=0\njsonlSha256=%s\nfullPhase7SampleSatisfied=false\noverallReplacementReady=false\n' \
  "${result_hash}" >"${EVIDENCE_DIR}/shared-state.status"
printf 'gitHead=%s\nrunId=%s\nsourceRevision=%s\nscenariosSha256=%s\nrunnerSha256=%s\nresultValidatorSha256=%s\nexpressAdapterSha256=%s\nfastapiAdapterSha256=%s\n' \
  "$(git -C "${REPO_DIR}" rev-parse HEAD)" "${RUN_ID}" "${SOURCE_REVISION}" \
  "${SCENARIOS_SHA256}" "${RUNNER_SHA256}" "${RESULT_VALIDATOR_SHA256}" "${EXPRESS_ADAPTER_SHA256}" \
  "${FASTAPI_ADAPTER_SHA256}" >"${EVIDENCE_DIR}/provenance.txt"
