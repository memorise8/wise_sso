#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly PHASE7_DIR="${SCRIPT_DIR}/phase7"
readonly ENV_EXAMPLE="${FASTAPI_DIR}/.env.example"
readonly PG_CONTAINER="wiseacct-sso-fastapi-dev-postgres"
readonly EXPRESS_CONTAINERS=(auth-server-app-1 auth-server-postgres-1 auth-server-redis-1)
readonly EXPRESS_PORT=4410 FASTAPI_PORT=4411
readonly RUN_ID="$(date -u +%Y%m%dt%H%M%S)_$$"
readonly GATE_EVIDENCE_ROOT="${FASTAPI_DIR}/evidence/phase7-shared"
readonly GATE_EVIDENCE_DIR="${GATE_EVIDENCE_ROOT}/${RUN_ID}"
readonly RUNTIME_EVIDENCE_ROOT="${FASTAPI_DIR}/evidence/phase7-shared-runtime"
readonly RUNTIME_EVIDENCE_DIR="${RUNTIME_EVIDENCE_ROOT}/${RUN_ID}"

if env | grep -Eq '^(PG[A-Z0-9_]*=|DATABASE_URL=|REDIS_URL=|COMPOSE_|DOCKER_HOST=|DOCKER_CONTEXT=|KUBECONFIG=|PORT=|WISEACCT_PHASE7_)'; then
  echo "Clear ambient database, Redis, Docker, Kubernetes, port, and Phase 7 overrides" >&2
  exit 2
fi
for command in curl docker flock git node npm python3 sha256sum; do command -v "${command}" >/dev/null; done
[[ -x "${FASTAPI_DIR}/.venv/bin/uvicorn" && -f "${ENV_EXAMPLE}" ]] || exit 2
for root in "${GATE_EVIDENCE_ROOT}" "${RUNTIME_EVIDENCE_ROOT}"; do
  [[ ! -L "${root}" && ( ! -e "${root}" || -d "${root}" ) ]] || exit 2
done
[[ ! -e "${GATE_EVIDENCE_DIR}" && ! -e "${RUNTIME_EVIDENCE_DIR}" ]] || exit 2

readonly GIT_COMMON_DIR="$(git -C "${REPO_DIR}" rev-parse --git-common-dir)"
readonly INTEGRATION_LOCK="$(cd -- "${GIT_COMMON_DIR}" && pwd)/wiseacct-fastapi-integration.lock"
exec 8>"${INTEGRATION_LOCK}"
flock --nonblock 8 || {
  echo "Another guarded FastAPI qualification or integration run owns the repository lock" >&2
  exit 4
}
[[ -z "$(git -C "${REPO_DIR}" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "Phase 7 shared-state runtime gate requires a clean committed worktree" >&2
  exit 2
}

readonly START_HEAD="$(git -C "${REPO_DIR}" rev-parse HEAD)"
readonly LAUNCHER_SHA256="$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)"
readonly GATE_SHA256="$(sha256sum "${PHASE7_DIR}/run-shared-state-core-gate.sh" | cut -d' ' -f1)"
readonly MATERIAL_SHA256="$(sha256sum "${PHASE7_DIR}/runtime_shared_material.py" | cut -d' ' -f1)"
readonly VALIDATOR_SHA256="$(sha256sum "${PHASE7_DIR}/validate_shared_inputs.py" | cut -d' ' -f1)"
readonly RESULT_VALIDATOR_SHA256="$(sha256sum "${PHASE7_DIR}/validate_shared_result.py" | cut -d' ' -f1)"
readonly PUBLISHER_SHA256="$(sha256sum "${PHASE7_DIR}/runtime_shared_publish.py" | cut -d' ' -f1)"

compose_up_attempted=0
shared_database_created=0
express_role_created=0
fastapi_role_created=0
express_pid=""
fastapi_pid=""
gate_exit=125
gate_verdict="NOT_RUN"
cleanup_status=0
integrity_status=0
private_temp_removed="false"
zero_candidate_resources="unknown"
express_snapshot_unchanged="false"
evidence_staging=""
gate_hash="$(printf 'NOT_CREATED' | sha256sum | cut -d' ' -f1)"
result_count="NOT_PROVEN"
concurrent_trial_count="NOT_PROVEN"
mixed_runtime_overlap_count="NOT_PROVEN"
overlap_mismatch_count="NOT_PROVEN"
launcher_exit=125
PRIVATE_DIR=""
before_snapshot=""
after_snapshot=""
cleanup_terminate_express="NOT_REQUIRED"
cleanup_terminate_fastapi="NOT_REQUIRED"
cleanup_drop_shared_database="NOT_REQUIRED"
cleanup_drop_express_role="NOT_REQUIRED"
cleanup_drop_fastapi_role="NOT_REQUIRED"
cleanup_redis_probe="NOT_REQUIRED"
cleanup_clear_redis_13="NOT_REQUIRED"
cleanup_candidate_compose_down="NOT_REQUIRED"
cleanup_express_snapshot="NOT_RUN"
cleanup_candidate_resources="NOT_RUN"
cleanup_private_temp_remove="NOT_RUN"

snapshot_express() {
  local destination="$1" container
  : >"${destination}"
  for container in "${EXPRESS_CONTAINERS[@]}"; do
    docker inspect --format '{{.Name}}|{{.Id}}|{{.RestartCount}}|{{.State.Status}}|{{.State.Health.Status}}|{{.State.StartedAt}}' \
      "${container}" >>"${destination}"
  done
}

candidate_resources_state() {
  local output status
  if output="$(${PHASE7_DIR}/runtime_candidate_state.py resources)"; then status=0; else status=$?; fi
  case "${status}:${output}" in
    0:EMPTY) candidate_state=EMPTY; return 0 ;;
    1:PRESENT) candidate_state=PRESENT; return 1 ;;
    *) candidate_state=ERROR; return 2 ;;
  esac
}

postgres_admin() {
  docker exec -i "${PG_CONTAINER}" psql --username fastapi_dev --dbname postgres --set ON_ERROR_STOP=1
}

terminate_runtime() {
  local pid="$1" stat_line stat_tail start_time attempt state current current_tail
  local -a fields
  [[ -n "${pid}" ]] || return 2
  if ! kill -0 "${pid}" 2>/dev/null; then wait "${pid}" 2>/dev/null || true; return 0; fi
  stat_line="$(<"/proc/${pid}/stat")" || return 1
  stat_tail="${stat_line##*) }"
  read -r -a fields <<<"${stat_tail}"
  [[ "${fields[1]:-}" == "$$" && -n "${fields[19]:-}" ]] || return 1
  start_time="${fields[19]}"
  same_process() {
    [[ -r "/proc/${pid}/stat" ]] || return 1
    current="$(<"/proc/${pid}/stat")" || return 1
    current_tail="${current##*) }"
    read -r -a fields <<<"${current_tail}"
    [[ "${fields[19]:-}" == "${start_time}" ]]
  }
  kill -TERM "${pid}" 2>/dev/null || { same_process && return 1; wait "${pid}" 2>/dev/null || true; return 0; }
  for attempt in {1..20}; do
    if ! same_process; then wait "${pid}" 2>/dev/null || true; return 0; fi
    current="$(<"/proc/${pid}/stat")" || continue
    current_tail="${current##*) }"
    read -r -a fields <<<"${current_tail}"
    state="${fields[0]:-}"
    if [[ "${state}" == Z ]]; then wait "${pid}" 2>/dev/null || true; return 0; fi
    sleep 0.1
  done
  kill -KILL "${pid}" 2>/dev/null || { same_process && return 1; }
  wait "${pid}" 2>/dev/null || true
  ! same_process
}

artifacts_are_stable() {
  local untracked gate_relative="fastapi-auth-server/evidence/phase7-shared/${RUN_ID}"
  [[ "$(git -C "${REPO_DIR}" rev-parse HEAD)" == "${START_HEAD}" ]] \
    && git -C "${REPO_DIR}" diff --quiet -- \
    && git -C "${REPO_DIR}" diff --cached --quiet -- \
    && [[ "$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)" == "${LAUNCHER_SHA256}" ]] \
    && [[ "$(sha256sum "${PHASE7_DIR}/run-shared-state-core-gate.sh" | cut -d' ' -f1)" == "${GATE_SHA256}" ]] \
    && [[ "$(sha256sum "${PHASE7_DIR}/runtime_shared_material.py" | cut -d' ' -f1)" == "${MATERIAL_SHA256}" ]] \
    && [[ "$(sha256sum "${PHASE7_DIR}/validate_shared_inputs.py" | cut -d' ' -f1)" == "${VALIDATOR_SHA256}" ]] \
    && [[ "$(sha256sum "${PHASE7_DIR}/validate_shared_result.py" | cut -d' ' -f1)" == "${RESULT_VALIDATOR_SHA256}" ]] \
    && [[ "$(sha256sum "${PHASE7_DIR}/runtime_shared_publish.py" | cut -d' ' -f1)" == "${PUBLISHER_SHA256}" ]] \
    || return 1
  while IFS= read -r -d '' untracked; do
    [[ "${untracked}" == "${gate_relative}/"* ]] || return 1
  done < <(git -C "${REPO_DIR}" ls-files --others --exclude-standard -z)
}

gate_evidence_is_complete() {
  [[ "${gate_verdict}" == PASS && "${gate_exit}" == 0 ]] \
    && [[ -d "${GATE_EVIDENCE_DIR}" && ! -L "${GATE_EVIDENCE_DIR}" ]] \
    && grep -Fxq 'status=PASS' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    && grep -Fxq 'resultCount=100' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    && grep -Fxq 'concurrentTrialCount=70' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    && grep -Fxq 'mixedRuntimeOverlapCount=70' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    && grep -Fxq 'overlapMismatchCount=0' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    && grep -Fxq 'fullPhase7SampleSatisfied=false' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    && grep -Fxq 'overallReplacementReady=false' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    && [[ -s "${GATE_EVIDENCE_DIR}/shared-state-results.jsonl" ]] \
    && [[ -s "${GATE_EVIDENCE_DIR}/provenance.txt" ]] \
    && [[ "$(find "${GATE_EVIDENCE_DIR}" -mindepth 1 ! -type f -print -quit)" == "" ]] \
    && [[ "$(find "${GATE_EVIDENCE_DIR}" -mindepth 1 -type f -perm /222 -print -quit)" == "" ]]
}

all_cleanup_steps_pass() {
  [[ "${cleanup_terminate_express}" == PASS \
    && "${cleanup_terminate_fastapi}" == PASS \
    && "${cleanup_drop_shared_database}" == PASS \
    && "${cleanup_drop_express_role}" == PASS \
    && "${cleanup_drop_fastapi_role}" == PASS \
    && "${cleanup_redis_probe}" == PASS \
    && "${cleanup_clear_redis_13}" == PASS \
    && "${cleanup_candidate_compose_down}" == PASS \
    && "${cleanup_express_snapshot}" == PASS \
    && "${cleanup_candidate_resources}" == PASS \
    && "${cleanup_private_temp_remove}" == PASS ]]
}

prepare_evidence() {
  mkdir -p -- "${RUNTIME_EVIDENCE_ROOT}" || return 1
  evidence_staging="$(mktemp -d "${RUNTIME_EVIDENCE_ROOT}/.${RUN_ID}.tmp.XXXXXXXX")" || return 1
  cp -- "${before_snapshot}" "${evidence_staging}/express-before.txt" || return 1
  cp -- "${after_snapshot}" "${evidence_staging}/express-after.txt" || return 1
  if [[ -d "${GATE_EVIDENCE_DIR}" && ! -L "${GATE_EVIDENCE_DIR}" ]]; then
    gate_hash="$(find "${GATE_EVIDENCE_DIR}" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
  fi
}

publish_evidence() {
  local final_status="$1" cleanup_result
  [[ -n "${evidence_staging}" && -d "${evidence_staging}" ]] || return 1
  cleanup_result="$([[ "${cleanup_status}" == 0 ]] && echo PASS || echo FAIL)"
  printf 'status=%s\nlauncherExit=%s\ngateVerdict=%s\ngateExit=%s\nintegrity=%s\ncleanup=%s\nexpressSnapshotUnchanged=%s\nzeroCandidateResources=%s\nprivateTempRemoved=%s\nresultCount=%s\nconcurrentTrialCount=%s\nmixedRuntimeOverlapCount=%s\noverlapMismatchCount=%s\nfullPhase7SampleSatisfied=false\noverallReplacementReady=false\n' \
    "${final_status}" "${launcher_exit}" "${gate_verdict}" "${gate_exit}" \
    "$([[ "${integrity_status}" == 0 ]] && echo PASS || echo FAIL)" "${cleanup_result}" \
    "${express_snapshot_unchanged}" "${zero_candidate_resources}" "${private_temp_removed}" \
    "${result_count}" "${concurrent_trial_count}" "${mixed_runtime_overlap_count}" \
    "${overlap_mismatch_count}" \
    >"${evidence_staging}/result.status"
  printf 'terminateExpress=%s\nterminateFastapi=%s\ndropSharedDatabase=%s\ndropExpressRole=%s\ndropFastapiRole=%s\nredisProbe=%s\nclearRedis13=%s\ncandidateComposeDown=%s\nexpressSnapshot=%s\ncandidateResources=%s\nprivateTempRemove=%s\n' \
    "${cleanup_terminate_express}" "${cleanup_terminate_fastapi}" \
    "${cleanup_drop_shared_database}" "${cleanup_drop_express_role}" \
    "${cleanup_drop_fastapi_role}" "${cleanup_redis_probe}" "${cleanup_clear_redis_13}" \
    "${cleanup_candidate_compose_down}" "${cleanup_express_snapshot}" \
    "${cleanup_candidate_resources}" "${cleanup_private_temp_remove}" \
    >"${evidence_staging}/cleanup.status"
  printf 'gitHead=%s\nrunId=%s\ngateEvidenceSha256=%s\nruntimeLauncherSha256=%s\n' \
    "${START_HEAD}" "${RUN_ID}" "${gate_hash}" "${LAUNCHER_SHA256}" \
    >"${evidence_staging}/provenance.txt"
  chmod -R a-w -- "${evidence_staging}" || return 1
  "${PHASE7_DIR}/runtime_shared_publish.py" \
    --staging "${evidence_staging}" --final "${RUNTIME_EVIDENCE_DIR}" || return 1
  evidence_staging=""
}

cleanup() {
  local original_status=$? redis_output redis_status
  launcher_exit="${original_status}"
  trap - EXIT INT TERM
  set +e
  if [[ -n "${express_pid}" ]]; then
    if terminate_runtime "${express_pid}"; then cleanup_terminate_express=PASS; else cleanup_terminate_express=FAIL; cleanup_status=1; fi
  fi
  if [[ -n "${fastapi_pid}" ]]; then
    if terminate_runtime "${fastapi_pid}"; then cleanup_terminate_fastapi=PASS; else cleanup_terminate_fastapi=FAIL; cleanup_status=1; fi
  fi
  if (( shared_database_created == 1 )); then
    if postgres_admin >/dev/null <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${P7_SHARED_DATABASE}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "${P7_SHARED_DATABASE}";
SQL
    then cleanup_drop_shared_database=PASS; else cleanup_drop_shared_database=FAIL; cleanup_status=1; fi
  fi
  if (( express_role_created == 1 )); then
    if printf 'DROP ROLE IF EXISTS "%s";\n' "${P7_EXPRESS_ROLE}" | postgres_admin >/dev/null; then cleanup_drop_express_role=PASS; else cleanup_drop_express_role=FAIL; cleanup_status=1; fi
  fi
  if (( fastapi_role_created == 1 )); then
    if printf 'DROP ROLE IF EXISTS "%s";\n' "${P7_FASTAPI_ROLE}" | postgres_admin >/dev/null; then cleanup_drop_fastapi_role=PASS; else cleanup_drop_fastapi_role=FAIL; cleanup_status=1; fi
  fi
  if (( compose_up_attempted == 1 )); then
    if redis_output="$(${PHASE7_DIR}/runtime_candidate_state.py redis-usable)"; then redis_status=0; else redis_status=$?; fi
    if [[ "${redis_status}:${redis_output}" == "0:USABLE" ]]; then
      cleanup_redis_probe=PASS
      if "${PHASE7_DIR}/runtime_redis_clear.py" --database 13 >/dev/null; then cleanup_clear_redis_13=PASS; else cleanup_clear_redis_13=FAIL; cleanup_status=1; fi
    else
      cleanup_redis_probe=FAIL
      cleanup_clear_redis_13=FAIL
      cleanup_status=1
    fi
    if "${SCRIPT_DIR}/dev-compose.sh" down "${ENV_EXAMPLE}" >/dev/null; then cleanup_candidate_compose_down=PASS; else cleanup_candidate_compose_down=FAIL; cleanup_status=1; fi
  fi
  if snapshot_express "${after_snapshot}" && cmp -s "${before_snapshot}" "${after_snapshot}"; then
    express_snapshot_unchanged=true; cleanup_express_snapshot=PASS
  else express_snapshot_unchanged=false; cleanup_express_snapshot=FAIL; cleanup_status=1; fi
  if candidate_resources_state; then
    zero_candidate_resources=true; cleanup_candidate_resources=PASS
  else
    zero_candidate_resources="$([[ "${candidate_state}" == PRESENT ]] && echo false || echo unknown)"
    cleanup_candidate_resources="$([[ "${candidate_state}" == PRESENT ]] && echo PRESENT || echo ERROR)"
    cleanup_status=1
  fi
  if ! artifacts_are_stable; then integrity_status=1; fi
  if (( original_status == 0 )) && ! gate_evidence_is_complete; then integrity_status=1; fi
  prepare_evidence || cleanup_status=1
  if "${PHASE7_DIR}/runtime_private_remove.py" --path "${PRIVATE_DIR}" \
      && [[ ! -e "${PRIVATE_DIR}" && ! -L "${PRIVATE_DIR}" ]]; then private_temp_removed=true; cleanup_private_temp_remove=PASS
  else private_temp_removed=false; cleanup_private_temp_remove=FAIL; cleanup_status=1; fi
  final_status=FAIL
  if (( original_status == 0 && cleanup_status == 0 && integrity_status == 0 )) \
      && all_cleanup_steps_pass; then final_status=PASS; fi
  if [[ "${final_status}" == PASS ]]; then
    launcher_exit=0
  else
    launcher_exit="$(( original_status == 0 ? 1 : original_status ))"
  fi
  if ! publish_evidence "${final_status}"; then
    cleanup_status=1
    final_status=FAIL
    launcher_exit=1
  fi
  if [[ "${final_status}" == PASS && "${cleanup_status}" == 0 ]]; then
    echo "Phase 7 shared-state-core-v1 gate passed; replacement remains unapproved"
    exit 0
  fi
  if [[ -n "${evidence_staging}" && -d "${evidence_staging}" ]]; then chmod -R u+w "${evidence_staging}"; rm -rf -- "${evidence_staging}"; fi
  echo "Phase 7 shared-state runtime gate failed; exact isolated cleanup was attempted" >&2
  exit "${launcher_exit}"
}

PRIVATE_DIR="$(mktemp -d /tmp/wiseacct-phase7-runtime.XXXXXXXX)"
chmod 0700 "${PRIVATE_DIR}"
before_snapshot="${PRIVATE_DIR}/express-before.txt"
after_snapshot="${PRIVATE_DIR}/express-after.txt"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot_express "${before_snapshot}"
if candidate_resources_state; then
  :
else
  resource_status=$?
  if (( resource_status == 1 )); then
    echo "Phase 7 shared-state gate requires zero candidate resources" >&2
  else
    echo "Phase 7 shared-state gate could not verify candidate resources" >&2
  fi
  exit 3
fi
"${PHASE7_DIR}/runtime_shared_material.py" \
  --example "${ENV_EXAMPLE}" --private-dir "${PRIVATE_DIR}" --run-id "${RUN_ID}" \
  --express-port "${EXPRESS_PORT}" --fastapi-port "${FASTAPI_PORT}"
# shellcheck disable=SC1090 -- trusted helper creates a private exact-mode file
source "${PRIVATE_DIR}/material.sh"

compose_up_attempted=1
"${SCRIPT_DIR}/dev-compose.sh" up "${ENV_EXAMPLE}" >"${PRIVATE_DIR}/compose.log" 2>&1
[[ "$(docker exec wiseacct-sso-fastapi-dev-redis redis-cli -n 13 DBSIZE)" == 0 ]] || {
  echo "Phase 7 shared-state gate requires empty Redis DB 13" >&2
  exit 5
}

shared_database_created=1
printf 'CREATE DATABASE "%s" OWNER fastapi_dev;\n' "${P7_SHARED_DATABASE}" | postgres_admin >/dev/null
(
  cd "${REPO_DIR}/auth-server"
  "${PHASE7_DIR}/runtime_exec.py" "${PRIVATE_DIR}/shared-admin.json" npx prisma migrate deploy
) >"${PRIVATE_DIR}/shared-migrate.log" 2>&1

express_role_created=1
printf 'CREATE ROLE "%s" LOGIN PASSWORD '\''%s'\'' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n' \
  "${P7_EXPRESS_ROLE}" "${P7_EXPRESS_PASSWORD}" | postgres_admin >/dev/null
fastapi_role_created=1
printf 'CREATE ROLE "%s" LOGIN PASSWORD '\''%s'\'' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n' \
  "${P7_FASTAPI_ROLE}" "${P7_FASTAPI_PASSWORD}" | postgres_admin >/dev/null
for role in "${P7_EXPRESS_ROLE}" "${P7_FASTAPI_ROLE}"; do
  docker exec -i "${PG_CONTAINER}" psql --username fastapi_dev --dbname "${P7_SHARED_DATABASE}" \
    --set ON_ERROR_STOP=1 >/dev/null <<SQL
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM "${role}";
GRANT CONNECT ON DATABASE "${P7_SHARED_DATABASE}" TO "${role}";
GRANT USAGE ON SCHEMA public TO "${role}";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "${role}";
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO "${role}";
SQL
done

(
  cd "${REPO_DIR}/auth-server"
  npm run build >/dev/null
  exec "${PHASE7_DIR}/runtime_exec.py" "${PRIVATE_DIR}/express-runtime.json" node \
    "${PHASE7_DIR}/runtime_express_loopback.mjs" "${REPO_DIR}/auth-server/dist/src/server.js"
) >"${PRIVATE_DIR}/express-runtime.log" 2>&1 &
express_pid=$!
(
  cd "${FASTAPI_DIR}"
  exec "${PHASE7_DIR}/runtime_exec.py" "${PRIVATE_DIR}/fastapi-runtime.json" \
    "${FASTAPI_DIR}/.venv/bin/uvicorn" wiseacct_sso.main:create_runtime_app --factory \
    --app-dir src --host 127.0.0.1 --port "${FASTAPI_PORT}" --no-proxy-headers \
    --no-server-header --no-access-log
) >"${PRIVATE_DIR}/fastapi-runtime.log" 2>&1 &
fastapi_pid=$!

for origin in "${P7_EXPRESS_URL}" "${P7_FASTAPI_URL}"; do
  ready=0
  for attempt in {1..100}; do
    if curl --fail --silent --show-error --output /dev/null "${origin}/healthz" 2>>"${PRIVATE_DIR}/readiness.stderr"; then ready=1; break; fi
    sleep 0.2
  done
  (( ready == 1 )) || { echo "A shared-state runtime did not become ready" >&2; exit 6; }
done
"${PHASE7_DIR}/runtime_listen_guard.py" --pid "${express_pid}" --port "${EXPRESS_PORT}"
"${PHASE7_DIR}/runtime_listen_guard.py" --pid "${fastapi_pid}" --port "${FASTAPI_PORT}"

mkdir -p -- "${GATE_EVIDENCE_DIR}"
set +e
WISEACCT_PHASE7_EXPRESS_DATABASE_URL="${P7_EXPRESS_NODE_DATABASE_URL}" \
WISEACCT_PHASE7_FASTAPI_DATABASE_URL="${P7_FASTAPI_PYTHON_DATABASE_URL}" \
WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL="${P7_FASTAPI_NODE_DATABASE_URL}" \
WISEACCT_PHASE7_EXPRESS_REDIS_URL="${P7_SHARED_REDIS_URL}" \
WISEACCT_PHASE7_FASTAPI_REDIS_URL="${P7_SHARED_REDIS_URL}" \
"${PHASE7_DIR}/run-shared-state-core-gate.sh" \
  "${P7_EXPRESS_URL}" "${P7_FASTAPI_URL}" \
  "${PRIVATE_DIR}/express-adapter.json" "${PRIVATE_DIR}/fastapi-adapter.json" \
  "${GATE_EVIDENCE_DIR}" >"${PRIVATE_DIR}/gate.log" 2>&1
gate_exit=$?
set -e
if (( gate_exit != 0 )) || ! grep -Fxq 'status=PASS' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    || ! grep -Fxq 'resultCount=100' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    || ! grep -Fxq 'concurrentTrialCount=70' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    || ! grep -Fxq 'mixedRuntimeOverlapCount=70' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    || ! grep -Fxq 'overlapMismatchCount=0' "${GATE_EVIDENCE_DIR}/shared-state.status" \
    || ! grep -Fxq 'overallReplacementReady=false' "${GATE_EVIDENCE_DIR}/shared-state.status"; then
  gate_verdict=FAIL
  exit "$(( gate_exit == 0 ? 7 : gate_exit ))"
fi
if grep -ERiq 'postgres(ql)?://|redis://|private key|password=|accessToken|refreshToken' "${GATE_EVIDENCE_DIR}"; then
  gate_verdict=FAIL
  echo "Shared-state gate evidence contains forbidden sensitive material" >&2
  exit 7
fi
gate_verdict=PASS
result_count=100
concurrent_trial_count=70
mixed_runtime_overlap_count=70
overlap_mismatch_count=0
chmod -R a-w -- "${GATE_EVIDENCE_DIR}"
