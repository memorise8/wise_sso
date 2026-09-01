#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly PHASE7_DIR="${SCRIPT_DIR}/phase7"
readonly CONTRACTS_DIR="${REPO_DIR}/contracts"
readonly EVIDENCE_ROOT="${FASTAPI_DIR}/evidence/phase7"

if env | grep -Eq '^(PG[A-Z0-9_]*=|DATABASE_URL=|REDIS_URL=|COMPOSE_|DOCKER_HOST=|DOCKER_CONTEXT=|KUBECONFIG=|PORT=)'; then
  echo "Clear ambient database, Redis, Docker, Kubernetes, and port overrides before Phase 7" >&2
  exit 2
fi

required=(
  WISEACCT_PHASE7_BASELINE_URL
  WISEACCT_PHASE7_CANDIDATE_URL
  WISEACCT_PHASE7_EXPRESS_DATABASE_URL
  WISEACCT_PHASE7_FASTAPI_DATABASE_URL
  WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL
  WISEACCT_PHASE7_EXPRESS_REDIS_URL
  WISEACCT_PHASE7_FASTAPI_REDIS_URL
  WISEACCT_PHASE7_EXPRESS_ADAPTER_CONFIG
  WISEACCT_PHASE7_FASTAPI_ADAPTER_CONFIG
)
for variable in "${required[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "Missing required Phase 7 input: ${variable}" >&2
    exit 2
  fi
done

readonly RUN_ID="${WISEACCT_PHASE7_RUN_ID:-$(date -u +%Y%m%dt%H%M%S).$$}"
if [[ ! "${RUN_ID}" =~ ^[a-z0-9][a-z0-9._-]{0,79}$ ]]; then
  echo "WISEACCT_PHASE7_RUN_ID has an unsafe format" >&2
  exit 2
fi

command -v git >/dev/null
command -v flock >/dev/null
command -v python3 >/dev/null
command -v sha256sum >/dev/null

readonly GIT_COMMON_DIR="$(git -C "${REPO_DIR}" rev-parse --git-common-dir)"
exec 8>"${GIT_COMMON_DIR}/wiseacct-fastapi-integration.lock"
if ! flock --nonblock 8; then
  echo "Another guarded FastAPI qualification or integration run owns the repository lock" >&2
  exit 4
fi

readonly GIT_HEAD="$(git -C "${REPO_DIR}" rev-parse --verify HEAD)"
if [[ -n "$(git -C "${REPO_DIR}" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "Phase 7 requires a clean committed worktree before evidence creation" >&2
  exit 2
fi

readonly PRIVATE_DIR="$(mktemp -d /tmp/wiseacct-phase7.XXXXXXXX)"
chmod 0700 "${PRIVATE_DIR}"
cleanup_private() {
  if [[ -d "${PRIVATE_DIR}" && "${PRIVATE_DIR}" == /tmp/wiseacct-phase7.* ]]; then
    rm -rf -- "${PRIVATE_DIR}"
  fi
}
trap cleanup_private EXIT
trap 'cleanup_private; exit 130' INT
trap 'cleanup_private; exit 143' TERM

topology="$(${PHASE7_DIR}/validate_inputs.py \
  --baseline "${WISEACCT_PHASE7_BASELINE_URL}" \
  --candidate "${WISEACCT_PHASE7_CANDIDATE_URL}" \
  --express-config "${WISEACCT_PHASE7_EXPRESS_ADAPTER_CONFIG}" \
  --fastapi-config "${WISEACCT_PHASE7_FASTAPI_ADAPTER_CONFIG}" \
  --snapshot-dir "${PRIVATE_DIR}" \
  --repo "${REPO_DIR}" \
  --evidence "${EVIDENCE_ROOT}")"
readonly EXPRESS_CONFIG_SNAPSHOT="${PRIVATE_DIR}/express.json"
readonly FASTAPI_CONFIG_SNAPSHOT="${PRIVATE_DIR}/fastapi.json"
readonly EXPRESS_CONFIG_SHA256="$(sha256sum "${EXPRESS_CONFIG_SNAPSHOT}" | cut -d' ' -f1)"
readonly FASTAPI_CONFIG_SHA256="$(sha256sum "${FASTAPI_CONFIG_SNAPSHOT}" | cut -d' ' -f1)"

snapshots_are_stable() {
  [[ "$(sha256sum "${EXPRESS_CONFIG_SNAPSHOT}" | cut -d' ' -f1)" == "${EXPRESS_CONFIG_SHA256}" ]] \
    && [[ "$(sha256sum "${FASTAPI_CONFIG_SNAPSHOT}" | cut -d' ' -f1)" == "${FASTAPI_CONFIG_SHA256}" ]]
}

readonly EVIDENCE_DIR="${EVIDENCE_ROOT}/${RUN_ID}"
if [[ -e "${EVIDENCE_DIR}" ]]; then
  echo "Phase 7 evidence run already exists: ${RUN_ID}" >&2
  exit 2
fi
mkdir -p -- "${EVIDENCE_DIR}"
finalized=0
finalize_interrupted() {
  local status=$?
  trap - EXIT INT TERM
  if (( finalized == 0 )); then
    printf 'status=ABORTED\noverallReplacementReady=false\n' >"${EVIDENCE_DIR}/result.status"
    chmod -R a-w -- "${EVIDENCE_DIR}" 2>/dev/null || true
  fi
  cleanup_private
  exit "${status}"
}
trap finalize_interrupted EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s\n' "${topology}" >"${EVIDENCE_DIR}/topology.json"

runner_sha256="$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)"
contract_sha256="$(sha256sum "${CONTRACTS_DIR}/bin/differential.py" | cut -d' ' -f1)"
gate_sha256="$(sha256sum "${PHASE7_DIR}/run-independent-contract-gate.sh" | cut -d' ' -f1)"
corpus_sha256="$(sha256sum "${CONTRACTS_DIR}/scenarios/public.json" "${CONTRACTS_DIR}/scenarios/guards.json" "${CONTRACTS_DIR}/scenarios/fixtures.json" | sha256sum | cut -d' ' -f1)"
printf 'gitHead=%s\ngitTree=clean\nrunId=%s\nrunnerSha256=%s\ncontractRunnerSha256=%s\nindependentGateSha256=%s\ncorpusSha256=%s\n' \
  "${GIT_HEAD}" "${RUN_ID}" "${runner_sha256}" "${contract_sha256}" "${gate_sha256}" "${corpus_sha256}" \
  >"${EVIDENCE_DIR}/provenance.txt"

provenance_is_stable() {
  [[ "$(git -C "${REPO_DIR}" rev-parse --verify HEAD)" == "${GIT_HEAD}" ]] \
    && [[ -z "$(git -C "${REPO_DIR}" status --porcelain=v1 --untracked-files=all -- . \
      ":(exclude)fastapi-auth-server/evidence/phase7/${RUN_ID}/**")" ]] \
    && [[ "$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)" == "${runner_sha256}" ]] \
    && [[ "$(sha256sum "${CONTRACTS_DIR}/bin/differential.py" | cut -d' ' -f1)" == "${contract_sha256}" ]] \
    && [[ "$(sha256sum "${PHASE7_DIR}/run-independent-contract-gate.sh" | cut -d' ' -f1)" == "${gate_sha256}" ]] \
    && [[ "$(sha256sum "${CONTRACTS_DIR}/scenarios/public.json" "${CONTRACTS_DIR}/scenarios/guards.json" "${CONTRACTS_DIR}/scenarios/fixtures.json" | sha256sum | cut -d' ' -f1)" == "${corpus_sha256}" ]] \
    && snapshots_are_stable
}

if "${PHASE7_DIR}/run-independent-contract-gate.sh" \
    "${WISEACCT_PHASE7_BASELINE_URL}" \
    "${WISEACCT_PHASE7_CANDIDATE_URL}" \
    "${EXPRESS_CONFIG_SNAPSHOT}" \
    "${FASTAPI_CONFIG_SNAPSHOT}" \
    "${EVIDENCE_DIR}"; then
  :
else
  contract_status=$?
  if provenance_is_stable; then
    printf 'status=FAIL\nfailedGate=independent-contract\ncontractScope=independent-stateful\noverallReplacementReady=false\n' \
      >"${EVIDENCE_DIR}/result.status"
  else
    contract_status=5
    printf 'status=FAIL\nfailedGate=provenance-stability\noverallReplacementReady=false\n' \
      >"${EVIDENCE_DIR}/result.status"
  fi
  finalized=1
  chmod -R a-w -- "${EVIDENCE_DIR}"
  cleanup_private
  trap - EXIT INT TERM
  exit "${contract_status}"
fi

placeholder_seen=0
for gate in performance security chaos backup-restore local-rollback; do
  if "${PHASE7_DIR}/run-placeholder-gate.sh" "${gate}" "${EVIDENCE_DIR}"; then
    gate_status=0
  else
    gate_status=$?
  fi
  if "${PHASE7_DIR}/check-placeholder-result.sh" \
      "${gate}" "${EVIDENCE_DIR}" "${gate_status}"; then
    placeholder_seen=1
  else
    gate_status=$?
    printf 'status=FAIL\nfailedGate=%s\noverallReplacementReady=false\n' "${gate}" \
      >"${EVIDENCE_DIR}/result.status"
    finalized=1
    chmod -R a-w -- "${EVIDENCE_DIR}"
    cleanup_private
    trap - EXIT INT TERM
    exit "${gate_status}"
  fi
done

if ! provenance_is_stable; then
  printf 'status=FAIL\nfailedGate=provenance-stability\noverallReplacementReady=false\n' \
    >"${EVIDENCE_DIR}/result.status"
  finalized=1
  chmod -R a-w -- "${EVIDENCE_DIR}"
  cleanup_private
  trap - EXIT INT TERM
  echo "Phase 7 source or commit provenance changed during qualification" >&2
  exit 5
fi

if (( placeholder_seen == 1 )); then
  printf 'status=INCOMPLETE\npassedGate=independent-contract\ncontractScope=independent-stateful\nremainingGaps=downstream-gates,incomplete-approved-core-flow-sample\nskippedGates=performance,security,chaos,backup-restore,local-rollback\noverallReplacementReady=false\n' \
    >"${EVIDENCE_DIR}/result.status"
  finalized=1
  chmod -R a-w -- "${EVIDENCE_DIR}"
  cleanup_private
  trap - EXIT INT TERM
  echo "Phase 7 independent contract gate passed, but qualification is incomplete" >&2
  exit 3
fi

printf 'status=PASS\noverallReplacementReady=false\nreason=production-cutover-requires-separate-approval\n' \
  >"${EVIDENCE_DIR}/result.status"
finalized=1
chmod -R a-w -- "${EVIDENCE_DIR}"
cleanup_private
trap - EXIT INT TERM
echo "Phase 7 provisional local qualification passed; production cutover is not approved"
