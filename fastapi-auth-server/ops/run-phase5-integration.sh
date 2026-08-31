#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly ENV_FILE="${FASTAPI_DIR}/.env.example"
readonly PG_CONTAINER="wiseacct-sso-fastapi-dev-postgres"
readonly REDIS_CONTAINER="wiseacct-sso-fastapi-dev-redis"
readonly EXPRESS_CONTAINERS=(auth-server-app-1 auth-server-postgres-1 auth-server-redis-1)
readonly EVIDENCE_DIR="${FASTAPI_DIR}/evidence/phase5"
readonly RUN_ID="$(date -u +%Y%m%d%H%M%S)_$$"
readonly TEST_DATABASE="fastapi_phase5_test_${RUN_ID}"
readonly RUNTIME_ROLE="phase5_runtime_${RUN_ID}"
readonly RUNTIME_PASSWORD="synthetic-phase5-runtime-only"
readonly ADMIN_URL="postgresql://fastapi_dev:synthetic-fastapi-db-only@127.0.0.1:5433/${TEST_DATABASE}"
readonly RUNTIME_URL="postgresql+asyncpg://${RUNTIME_ROLE}:${RUNTIME_PASSWORD}@127.0.0.1:5433/${TEST_DATABASE}"
readonly NODE_RUNTIME_URL="postgresql://${RUNTIME_ROLE}:${RUNTIME_PASSWORD}@127.0.0.1:5433/${TEST_DATABASE}"
readonly REDIS_URL="redis://127.0.0.1:6380/15"

if env | grep -Eq '^(PG[A-Z0-9_]*=|COMPOSE_|DOCKER_HOST=|DOCKER_CONTEXT=|WISEACCT_FASTAPI_DEV_ENV_FILE=|AUTH_DB_[A-Z0-9_]*=|DATABASE_URL=|REDIS_URL=|PORT=)'; then
  echo "Clear ambient Compose/Docker/SSO/libpq overrides before Phase 5" >&2
  exit 2
fi

command -v flock >/dev/null
readonly GIT_COMMON_DIR="$(git -C "${REPO_DIR}" rev-parse --git-common-dir)"
exec 8>"${GIT_COMMON_DIR}/wiseacct-fastapi-integration.lock"
exec 9>"${GIT_COMMON_DIR}/wiseacct-phase4-integration.lock"
if ! flock --nonblock 8 || ! flock --nonblock 9; then
  echo "Another guarded FastAPI integration run owns the repository lock" >&2
  exit 4
fi

stack_started=0
database_created=0
role_created=0
cleanup_status=0

mkdir -p "${EVIDENCE_DIR}"
rm -f \
  "${EVIDENCE_DIR}/express-after.txt" \
  "${EVIDENCE_DIR}/express-before.txt" \
  "${EVIDENCE_DIR}/phase5-junit.xml" \
  "${EVIDENCE_DIR}/phase5-pytest.txt" \
  "${EVIDENCE_DIR}/provenance.txt"
cat >"${EVIDENCE_DIR}/result.md" <<'EOF'
# Phase 5 provisional isolated integration result

- Guarded real PostgreSQL/Redis lane: RUNNING
- Overall migration: **NOT REPLACEMENT READY**

This evidence is PROVISIONAL and is not production replacement or cutover approval.
EOF

snapshot_express() {
  local destination="$1"
  : >"${destination}"
  local container
  for container in "${EXPRESS_CONTAINERS[@]}"; do
    docker inspect --format '{{.Name}}|{{.Id}}|{{.RestartCount}}|{{.State.Health.Status}}|{{.State.StartedAt}}' \
      "${container}" >>"${destination}"
  done
  curl --fail --silent --show-error --output /dev/null \
    --write-out 'http://192.168.0.4:4000/healthz|%{http_code}\n' \
    http://192.168.0.4:4000/healthz >>"${destination}"
}

postgres_admin() {
  docker exec "${PG_CONTAINER}" psql --username fastapi_dev --dbname postgres \
    --set ON_ERROR_STOP=1 "$@"
}

candidate_resources_remain() {
  docker ps -a --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
    --format '{{.Names}}' | grep -q . \
    || docker network ls --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
      --format '{{.Name}}' | grep -q . \
    || docker volume ls --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
      --format '{{.Name}}' | grep -q .
}

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  set +e

  if (( database_created == 1 )); then
    postgres_admin --command="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${TEST_DATABASE}' AND pid <> pg_backend_pid();" >/dev/null
    postgres_admin --command="DROP DATABASE IF EXISTS \"${TEST_DATABASE}\";" >/dev/null
  fi
  if (( role_created == 1 )); then
    postgres_admin --command="DROP ROLE IF EXISTS \"${RUNTIME_ROLE}\";" >/dev/null
  fi
  if (( stack_started == 1 )); then
    "${SCRIPT_DIR}/dev-compose.sh" down "${ENV_FILE}" >/dev/null
  fi

  snapshot_express "${EVIDENCE_DIR}/express-after.txt"
  if ! cmp -s "${EVIDENCE_DIR}/express-before.txt" "${EVIDENCE_DIR}/express-after.txt"; then
    echo "Express runtime identity/health/restart snapshot changed" >&2
    cleanup_status=1
  fi
  if candidate_resources_remain; then
    echo "Candidate Compose resources remain after cleanup" >&2
    cleanup_status=1
  fi

  if (( original_status == 0 && cleanup_status == 0 )); then
    cat >"${EVIDENCE_DIR}/result.md" <<'EOF'
# Phase 5 provisional isolated integration result

- Guarded real PostgreSQL/Redis lane: PASS
- Overall migration: **NOT REPLACEMENT READY**
- Scope: disposable PostgreSQL `_test_` database on `127.0.0.1:5433`; isolated Redis DB 15 on `127.0.0.1:6380`; fake mail/provider only
- Schema owner: checked-in Prisma migrations; Python runtime role received DML only; DDL denied with SQLSTATE `42501`
- Phase 5 proofs: hash-only 24-hour verification and 1-hour password-reset records; consume-then-domain-failure commit boundaries; mail ordering; local STARTTLS and implicit-TLS/Resend fake-SMTP delivery/reject/timeout/no-STARTTLS boundaries; self-signed local HTTPS provider TLS rejection; 20-way single-consumer confirmation/reset races; default role activation; pending-password attach; reset counter clearing and refresh revocation; OAuth state 600-second destructive wrong-provider consume; handoff hashed-key 120-second binding-preserving raw CAS; Node↔Python JSON consumption; OAuth identity attach/pending replacement/subject reservation/same-provider race; real Express/Prisma↔FastAPI/SQLAlchemy mixed-writer same-provider, verified-email attach, and subject-reservation races; exchange consume-before-token-issue failure
- Network: no external provider or mail calls; localhost candidate services only
- Cleanup: exact test database, DML role, Compose containers/network/volume removed; zero candidate resources remain
- Express: container IDs, start times, restart counts, health states, and HTTP 200 unchanged

This evidence is PROVISIONAL and is not production replacement or cutover approval.
EOF
    echo "Phase 5 provisional integration gate passed"
    exit 0
  fi
  cat >"${EVIDENCE_DIR}/result.md" <<'EOF'
# Phase 5 provisional isolated integration result

- Guarded real PostgreSQL/Redis lane: FAIL
- Overall migration: **NOT REPLACEMENT READY**
- Cleanup was attempted for the exact synthetic database, role, and guarded Compose resources.
- Production data, credentials, routing, providers, mail, and cutover were never in scope.

This evidence is PROVISIONAL and is not production replacement or cutover approval.
EOF
  exit "$(( original_status == 0 ? 1 : original_status ))"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

command -v curl >/dev/null
command -v docker >/dev/null
command -v node >/dev/null
command -v npm >/dev/null
command -v uv >/dev/null
snapshot_express "${EVIDENCE_DIR}/express-before.txt"

if candidate_resources_remain; then
  echo "Phase 5 requires zero pre-existing candidate Compose resources" >&2
  exit 3
fi

"${SCRIPT_DIR}/dev-compose.sh" up "${ENV_FILE}"
stack_started=1

if [[ "$(docker exec "${REDIS_CONTAINER}" redis-cli -n 15 DBSIZE)" != "0" ]]; then
  echo "Phase 5 requires an empty isolated Redis DB 15" >&2
  exit 5
fi

source_tree_sha256="$(
  find "${FASTAPI_DIR}/src" -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    | sha256sum \
    | cut -d' ' -f1
)"
image_id="$(docker inspect --format '{{.Image}}' wiseacct-sso-fastapi-dev-app)"
git_head="$(git -C "${REPO_DIR}" rev-parse HEAD)"
python_lock_sha256="$(sha256sum "${FASTAPI_DIR}/uv.lock" | cut -d' ' -f1)"
node_lock_sha256="$(sha256sum "${REPO_DIR}/auth-server/package-lock.json" | cut -d' ' -f1)"
printf 'gitHead=%s\nsourceTreeSha256=%s\nimageId=%s\nrunId=%s\npythonLockSha256=%s\nnodeLockSha256=%s\n' \
  "${git_head}" "${source_tree_sha256}" "${image_id}" "${RUN_ID}" \
  "${python_lock_sha256}" "${node_lock_sha256}" \
  >"${EVIDENCE_DIR}/provenance.txt"

postgres_admin --command="CREATE DATABASE \"${TEST_DATABASE}\" OWNER fastapi_dev;"
database_created=1
(
  cd "${REPO_DIR}/auth-server"
  npm ci --no-audit --no-fund
  DATABASE_URL="${ADMIN_URL}" npx prisma migrate deploy
)

postgres_admin --command="CREATE ROLE \"${RUNTIME_ROLE}\" LOGIN PASSWORD '${RUNTIME_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;"
role_created=1
docker exec "${PG_CONTAINER}" psql --username fastapi_dev --dbname "${TEST_DATABASE}" \
  --set ON_ERROR_STOP=1 \
  --command="REVOKE CREATE ON SCHEMA public FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM \"${RUNTIME_ROLE}\"; GRANT CONNECT ON DATABASE \"${TEST_DATABASE}\" TO \"${RUNTIME_ROLE}\"; GRANT USAGE ON SCHEMA public TO \"${RUNTIME_ROLE}\"; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"${RUNTIME_ROLE}\";"

(
  cd "${FASTAPI_DIR}"
  WISEACCT_PHASE5_INTEGRATION=1 \
  WISEACCT_PHASE5_DATABASE_URL="${RUNTIME_URL}" \
  WISEACCT_PHASE5_NODE_DATABASE_URL="${NODE_RUNTIME_URL}" \
  WISEACCT_PHASE5_REDIS_URL="${REDIS_URL}" \
  WISEACCT_PHASE5_RUN_ID="${RUN_ID}" \
  uv run --frozen pytest -vv --junitxml="${EVIDENCE_DIR}/phase5-junit.xml" \
    tests/integration/test_phase5_auth_runtime.py \
    | tee "${EVIDENCE_DIR}/phase5-pytest.txt"
)

test_count="$(python3 -c 'import sys, xml.etree.ElementTree as ET; print(len(ET.parse(sys.argv[1]).findall(".//testcase")))' "${EVIDENCE_DIR}/phase5-junit.xml")"
printf 'testsCollected=%s\n' "${test_count}" >>"${EVIDENCE_DIR}/provenance.txt"

if [[ "$(docker exec "${REDIS_CONTAINER}" redis-cli -n 15 DBSIZE)" != "0" ]]; then
  echo "Phase 5 Redis DB is not empty after the suite" >&2
  exit 6
fi
