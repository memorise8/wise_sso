#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly PHASE7_DIR="${SCRIPT_DIR}/phase7"
readonly ENV_EXAMPLE="${FASTAPI_DIR}/.env.example"
readonly PG_CONTAINER="wiseacct-sso-fastapi-dev-postgres"
readonly REDIS_CONTAINER="wiseacct-sso-fastapi-dev-redis"
readonly EXPRESS_CONTAINERS=(auth-server-app-1 auth-server-postgres-1 auth-server-redis-1)
readonly EXPRESS_PORT=4410
readonly FASTAPI_PORT=4411
readonly RUN_ID="$(date -u +%Y%m%dt%H%M%S)_$$"
readonly RUNTIME_EVIDENCE_ROOT="${FASTAPI_DIR}/evidence/phase7-runtime"
readonly RUNTIME_EVIDENCE_DIR="${RUNTIME_EVIDENCE_ROOT}/${RUN_ID}"
readonly QUALIFICATION_EVIDENCE_DIR="${FASTAPI_DIR}/evidence/phase7/${RUN_ID}"

if env | grep -Eq '^(PG[A-Z0-9_]*=|DATABASE_URL=|REDIS_URL=|COMPOSE_|DOCKER_HOST=|DOCKER_CONTEXT=|KUBECONFIG=|PORT=|WISEACCT_PHASE7_)'; then
  echo "Clear ambient database, Redis, Docker, Kubernetes, port, and Phase 7 overrides" >&2
  exit 2
fi

for command in curl docker flock git node npm python3 sha256sum; do
  command -v "${command}" >/dev/null
done
[[ -x "${FASTAPI_DIR}/.venv/bin/uvicorn" ]] || {
  echo "The committed FastAPI virtual environment is required" >&2
  exit 2
}
[[ -f "${ENV_EXAMPLE}" ]] || exit 2

readonly GIT_COMMON_DIR="$(git -C "${REPO_DIR}" rev-parse --git-common-dir)"
readonly INTEGRATION_LOCK="$(cd -- "${GIT_COMMON_DIR}" && pwd)/wiseacct-fastapi-integration.lock"
exec 8>"${INTEGRATION_LOCK}"
if ! flock --nonblock 8; then
  echo "Another guarded FastAPI qualification or integration run owns the repository lock" >&2
  exit 4
fi
if [[ -e "${RUNTIME_EVIDENCE_DIR}" ]]; then
  echo "Phase 7 runtime evidence run already exists: ${RUN_ID}" >&2
  exit 2
fi
if [[ -L "${RUNTIME_EVIDENCE_ROOT}" ]] \
    || [[ -e "${RUNTIME_EVIDENCE_ROOT}" && ! -d "${RUNTIME_EVIDENCE_ROOT}" ]]; then
  echo "Phase 7 runtime evidence root must be a repository directory" >&2
  exit 2
fi

compose_up_attempted=0
express_database_created=0
fastapi_database_created=0
express_role_created=0
fastapi_role_created=0
express_pid=""
fastapi_pid=""
qualification_exit=125
qualification_verdict="NOT_RUN"
cleanup_status=0
candidate_state="UNKNOWN"
zero_candidate_resources="unknown"
express_snapshot_unchanged="false"
private_temp_removed="false"
evidence_staging=""
qualification_hash="NOT_CREATED"
PRIVATE_DIR=""
before_snapshot=""
after_snapshot=""

snapshot_express() {
  local destination="$1"
  : >"${destination}"
  local container
  for container in "${EXPRESS_CONTAINERS[@]}"; do
    docker inspect --format '{{.Name}}|{{.Id}}|{{.RestartCount}}|{{.State.Status}}|{{.State.Health.Status}}|{{.State.StartedAt}}' \
      "${container}" >>"${destination}"
  done
}

candidate_resources_state() {
  local output status
  if output="$(${PHASE7_DIR}/runtime_candidate_state.py resources)"; then
    status=0
  else
    status=$?
  fi
  case "${status}:${output}" in
    0:EMPTY) candidate_state="EMPTY" ;;
    1:PRESENT) candidate_state="PRESENT" ;;
    *) candidate_state="ERROR"; status=2 ;;
  esac
  return "${status}"
}

postgres_admin() {
  docker exec -i "${PG_CONTAINER}" psql --username fastapi_dev --dbname postgres \
    --set ON_ERROR_STOP=1
}

terminate_runtime() {
  local pid="$1"
  [[ -n "${pid}" ]] || return 0
  if ! kill -0 "${pid}" 2>/dev/null; then
    wait "${pid}" 2>/dev/null || true
    return 0
  fi
  local parent
  parent="$(awk '/^PPid:/ { print $2 }' "/proc/${pid}/status" 2>/dev/null)" || return 1
  [[ "${parent}" == "$$" ]] || return 1
  kill -TERM "${pid}" 2>/dev/null || return 1
  local attempt state
  for attempt in {1..20}; do
    if [[ ! -e "/proc/${pid}/stat" ]]; then
      wait "${pid}" 2>/dev/null || true
      ! kill -0 "${pid}" 2>/dev/null
      return
    fi
    state="$(awk '{ print $3 }' "/proc/${pid}/stat" 2>/dev/null)"
    if [[ "${state}" == "Z" ]]; then
      wait "${pid}" 2>/dev/null || true
      ! kill -0 "${pid}" 2>/dev/null
      return
    fi
    sleep 0.1
  done
  kill -KILL "${pid}" 2>/dev/null || return 1
  wait "${pid}" 2>/dev/null || true
  ! kill -0 "${pid}" 2>/dev/null
}

prepare_evidence_staging() {
  [[ ! -e "${RUNTIME_EVIDENCE_DIR}" ]] || return 1
  mkdir -p -- "${RUNTIME_EVIDENCE_ROOT}" || return 1
  evidence_staging="$(mktemp -d "${RUNTIME_EVIDENCE_ROOT}/.${RUN_ID}.tmp.XXXXXXXX")" || return 1
  cp -- "${before_snapshot}" "${evidence_staging}/express-before.txt" || {
    rm -rf -- "${evidence_staging}"
    evidence_staging=""
    return 1
  }
  cp -- "${after_snapshot}" "${evidence_staging}/express-after.txt" || {
    rm -rf -- "${evidence_staging}"
    evidence_staging=""
    return 1
  }
  if [[ -d "${QUALIFICATION_EVIDENCE_DIR}" ]]; then
    qualification_hash="$(find "${QUALIFICATION_EVIDENCE_DIR}" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
  fi
}

discard_evidence_staging() {
  if [[ -n "${evidence_staging}" && -d "${evidence_staging}" ]]; then
    chmod -R u+w -- "${evidence_staging}" 2>/dev/null || true
    rm -rf -- "${evidence_staging}"
  fi
}

publish_evidence() {
  local final_status="$1"
  [[ -n "${evidence_staging}" && -d "${evidence_staging}" ]] || return 1
  printf 'status=%s\nqualificationVerdict=%s\nqualificationExit=%s\ncleanup=%s\nexpressSnapshotUnchanged=%s\nzeroCandidateResources=%s\noverallReplacementReady=false\n' \
    "${final_status}" "${qualification_verdict}" "${qualification_exit}" \
    "$([[ "${cleanup_status}" == 0 ]] && echo PASS || echo FAIL)" \
    "${express_snapshot_unchanged}" \
    "${zero_candidate_resources}" \
    >"${evidence_staging}/result.status"
  printf 'privateTempRemoved=%s\n' "${private_temp_removed}" >>"${evidence_staging}/result.status"
  printf 'gitHead=%s\nrunId=%s\nqualificationRunId=%s\nqualificationEvidenceSha256=%s\nruntimeLauncherSha256=%s\n' \
    "$(git -C "${REPO_DIR}" rev-parse HEAD)" "${RUN_ID}" "${RUN_ID}" \
    "${qualification_hash}" "$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)" \
    >"${evidence_staging}/provenance.txt"
  if [[ "$(find "${evidence_staging}" -mindepth 1 -maxdepth 1 -type f | wc -l)" != 4 ]] \
      || [[ -n "$(find "${evidence_staging}" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]] \
      || ! grep -Fxq "status=${final_status}" "${evidence_staging}/result.status" \
      || ! grep -Fxq "zeroCandidateResources=${zero_candidate_resources}" "${evidence_staging}/result.status" \
      || ! grep -Fxq "privateTempRemoved=${private_temp_removed}" "${evidence_staging}/result.status" \
      || grep -ERiq 'postgres(ql)?://|redis://|private key|password=|runtime\.log|qualification\.log' "${evidence_staging}"; then
    discard_evidence_staging
    return 1
  fi
  chmod -R a-w -- "${evidence_staging}" || {
    discard_evidence_staging
    return 1
  }
  if ! "${PHASE7_DIR}/runtime_publish.py" --staging "${evidence_staging}" --final "${RUNTIME_EVIDENCE_DIR}"; then
    discard_evidence_staging
    return 1
  fi
  evidence_staging=""
}

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  set +e
  terminate_runtime "${express_pid}" || cleanup_status=1
  terminate_runtime "${fastapi_pid}" || cleanup_status=1
  if (( express_database_created == 1 )); then
    postgres_admin >/dev/null <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${P7_EXPRESS_DATABASE}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "${P7_EXPRESS_DATABASE}";
SQL
    (( $? == 0 )) || cleanup_status=1
  fi
  if (( fastapi_database_created == 1 )); then
    postgres_admin >/dev/null <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${P7_FASTAPI_DATABASE}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "${P7_FASTAPI_DATABASE}";
SQL
    (( $? == 0 )) || cleanup_status=1
  fi
  if (( express_role_created == 1 )); then
    printf 'DROP ROLE IF EXISTS "%s";\n' "${P7_EXPRESS_ROLE}" | postgres_admin >/dev/null
    (( $? == 0 )) || cleanup_status=1
  fi
  if (( fastapi_role_created == 1 )); then
    printf 'DROP ROLE IF EXISTS "%s";\n' "${P7_FASTAPI_ROLE}" | postgres_admin >/dev/null
    (( $? == 0 )) || cleanup_status=1
  fi
  if (( compose_up_attempted == 1 )); then
    if "${PHASE7_DIR}/runtime_candidate_state.py" redis-usable >/dev/null; then
      "${PHASE7_DIR}/runtime_redis_clear.py" --database 13 >/dev/null || cleanup_status=1
      "${PHASE7_DIR}/runtime_redis_clear.py" --database 14 >/dev/null || cleanup_status=1
    else
      redis_state=$?
      (( redis_state == 1 )) || cleanup_status=1
    fi
    "${SCRIPT_DIR}/dev-compose.sh" down "${ENV_EXAMPLE}" >/dev/null || cleanup_status=1
  fi
  snapshot_express "${after_snapshot}" || cleanup_status=1
  if cmp -s "${before_snapshot}" "${after_snapshot}"; then
    express_snapshot_unchanged="true"
  else
    express_snapshot_unchanged="false"
    cleanup_status=1
  fi
  if candidate_resources_state; then
    zero_candidate_resources="true"
  else
    zero_candidate_resources="$([[ "${candidate_state}" == PRESENT ]] && echo false || echo unknown)"
    cleanup_status=1
  fi
  prepare_evidence_staging || cleanup_status=1
  if "${PHASE7_DIR}/runtime_private_remove.py" --path "${PRIVATE_DIR}"; then
    private_temp_removed="true"
  else
    private_temp_removed="false"
    cleanup_status=1
  fi
  final_status=FAIL
  if (( original_status == 0 && cleanup_status == 0 )); then
    final_status=PASS
  fi
  publish_evidence "${final_status}" || cleanup_status=1
  discard_evidence_staging
  if (( original_status == 0 && cleanup_status == 0 )); then
    echo "Phase 7 disposable independent runtime gate passed; replacement remains unapproved"
    exit 0
  fi
  echo "Phase 7 disposable runtime gate failed; exact isolated cleanup was attempted" >&2
  exit "$(( original_status == 0 ? 1 : original_status ))"
}
PRIVATE_DIR="$(mktemp -d /tmp/wiseacct-phase7-runtime.XXXXXXXX)"
before_snapshot="${PRIVATE_DIR}/express-before.txt"
after_snapshot="${PRIVATE_DIR}/express-after.txt"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 0700 "${PRIVATE_DIR}"

snapshot_express "${before_snapshot}"
if candidate_resources_state; then
  :
else
  resource_status=$?
  if (( resource_status == 1 )); then
    echo "Phase 7 requires zero pre-existing candidate Compose resources" >&2
  else
    echo "Phase 7 could not verify candidate resource state" >&2
  fi
  exit 3
fi
if [[ -n "$(git -C "${REPO_DIR}" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "Phase 7 runtime qualification requires a clean committed worktree" >&2
  exit 2
fi

"${PHASE7_DIR}/runtime_material.py" \
  --example "${ENV_EXAMPLE}" --private-dir "${PRIVATE_DIR}" --run-id "${RUN_ID}" \
  --express-port "${EXPRESS_PORT}" --fastapi-port "${FASTAPI_PORT}"
# shellcheck disable=SC1090 -- generated by the committed trusted helper into a private directory
source "${PRIVATE_DIR}/material.sh"

compose_up_attempted=1
"${SCRIPT_DIR}/dev-compose.sh" up "${ENV_EXAMPLE}" >"${PRIVATE_DIR}/compose.log" 2>&1
for database in 13 14; do
  if [[ "$(docker exec "${REDIS_CONTAINER}" redis-cli -n "${database}" DBSIZE)" != "0" ]]; then
    echo "Phase 7 requires empty isolated Redis DB ${database}" >&2
    exit 5
  fi
done

express_database_created=1
fastapi_database_created=1
printf 'CREATE DATABASE "%s" OWNER fastapi_dev;\n' "${P7_EXPRESS_DATABASE}" | postgres_admin >/dev/null
printf 'CREATE DATABASE "%s" OWNER fastapi_dev;\n' "${P7_FASTAPI_DATABASE}" | postgres_admin >/dev/null

(
  cd "${REPO_DIR}/auth-server"
  "${PHASE7_DIR}/runtime_exec.py" "${PRIVATE_DIR}/express-admin.json" npx prisma migrate deploy
) >"${PRIVATE_DIR}/express-migrate.log" 2>&1
(
  cd "${REPO_DIR}/auth-server"
  "${PHASE7_DIR}/runtime_exec.py" "${PRIVATE_DIR}/fastapi-admin.json" npx prisma migrate deploy
) >"${PRIVATE_DIR}/fastapi-migrate.log" 2>&1

express_role_created=1
fastapi_role_created=1
printf 'CREATE ROLE "%s" LOGIN PASSWORD '\''%s'\'' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n' \
  "${P7_EXPRESS_ROLE}" "${P7_EXPRESS_PASSWORD}" | postgres_admin >/dev/null
printf 'CREATE ROLE "%s" LOGIN PASSWORD '\''%s'\'' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;\n' \
  "${P7_FASTAPI_ROLE}" "${P7_FASTAPI_PASSWORD}" | postgres_admin >/dev/null
for pair in "${P7_EXPRESS_DATABASE}:${P7_EXPRESS_ROLE}" "${P7_FASTAPI_DATABASE}:${P7_FASTAPI_ROLE}"; do
  database="${pair%%:*}"
  role="${pair##*:}"
  docker exec -i "${PG_CONTAINER}" psql --username fastapi_dev --dbname "${database}" \
    --set ON_ERROR_STOP=1 >/dev/null <<SQL
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM "${role}";
GRANT CONNECT ON DATABASE "${database}" TO "${role}";
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
    if curl --fail --silent --show-error --output /dev/null "${origin}/healthz"; then
      ready=1
      break
    fi
    sleep 0.2
  done
  if (( ready == 0 )); then
    echo "An isolated Phase 7 runtime did not become ready" >&2
    exit 6
  fi
done
if ! kill -0 "${express_pid}" 2>/dev/null || ! kill -0 "${fastapi_pid}" 2>/dev/null; then
  echo "A readiness response did not belong to both launched Phase 7 runtimes" >&2
  exit 6
fi
"${PHASE7_DIR}/runtime_listen_guard.py" --pid "${express_pid}" --port "${EXPRESS_PORT}" || {
  echo "The launched Express PID does not own its expected LISTEN socket" >&2
  exit 6
}
"${PHASE7_DIR}/runtime_listen_guard.py" --pid "${fastapi_pid}" --port "${FASTAPI_PORT}" || {
  echo "The launched FastAPI PID does not own its expected LISTEN socket" >&2
  exit 6
}

set +e
WISEACCT_PHASE7_INTEGRATION_LOCK_FD=8 \
WISEACCT_PHASE7_RUN_ID="${RUN_ID}" \
WISEACCT_PHASE7_BASELINE_URL="${P7_EXPRESS_URL}" \
WISEACCT_PHASE7_CANDIDATE_URL="${P7_FASTAPI_URL}" \
WISEACCT_PHASE7_EXPRESS_DATABASE_URL="${P7_EXPRESS_NODE_DATABASE_URL}" \
WISEACCT_PHASE7_FASTAPI_DATABASE_URL="${P7_FASTAPI_PYTHON_DATABASE_URL}" \
WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL="${P7_FASTAPI_NODE_DATABASE_URL}" \
WISEACCT_PHASE7_EXPRESS_REDIS_URL="${P7_EXPRESS_REDIS_URL}" \
WISEACCT_PHASE7_FASTAPI_REDIS_URL="${P7_FASTAPI_REDIS_URL}" \
WISEACCT_PHASE7_EXPRESS_ADAPTER_CONFIG="${PRIVATE_DIR}/express-adapter.json" \
WISEACCT_PHASE7_FASTAPI_ADAPTER_CONFIG="${PRIVATE_DIR}/fastapi-adapter.json" \
"${SCRIPT_DIR}/run-phase7-qualification.sh" >"${PRIVATE_DIR}/qualification.log" 2>&1
qualification_exit=$?
set -e

if (( qualification_exit == 3 )) \
    && grep -Fxq 'status=INCOMPLETE' "${QUALIFICATION_EVIDENCE_DIR}/result.status" \
    && grep -Fxq 'passedGate=independent-contract' "${QUALIFICATION_EVIDENCE_DIR}/result.status"; then
  qualification_verdict="INCOMPLETE_INDEPENDENT_PASS"
elif (( qualification_exit == 0 )) \
    && grep -Fxq 'status=PASS' "${QUALIFICATION_EVIDENCE_DIR}/result.status"; then
  qualification_verdict="PASS"
else
  qualification_verdict="FAIL"
  echo "Phase 7 qualification did not produce an acceptable verified result" >&2
  exit "$(( qualification_exit == 0 ? 7 : qualification_exit ))"
fi
