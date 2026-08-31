#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly ENV_FILE="${FASTAPI_DIR}/.env.example"
readonly PG_CONTAINER="wiseacct-sso-fastapi-dev-postgres"
readonly EXPRESS_CONTAINERS=(auth-server-app-1 auth-server-postgres-1 auth-server-redis-1)
readonly EVIDENCE_DIR="${FASTAPI_DIR}/evidence/phase4"
readonly RUN_ID="$(date -u +%Y%m%d%H%M%S)_$$"
readonly TEST_DATABASE="fastapi_phase4_test_${RUN_ID}"
readonly RUNTIME_ROLE="phase4_runtime_${RUN_ID}"
readonly RUNTIME_PASSWORD="synthetic-phase4-runtime-only"
readonly ADMIN_URL="postgresql://fastapi_dev:synthetic-fastapi-db-only@127.0.0.1:5433/${TEST_DATABASE}"
readonly RUNTIME_URL="postgresql+asyncpg://${RUNTIME_ROLE}:${RUNTIME_PASSWORD}@127.0.0.1:5433/${TEST_DATABASE}"
readonly REDIS_URL="redis://127.0.0.1:6380/15"
readonly REDIS_PREFIX="wiseacct:rate-limit:phase4-${RUN_ID}"
readonly HTTP_PORT="4011"

if env | grep -Eq '^(PG[A-Z0-9_]*=|COMPOSE_|DOCKER_HOST=|DOCKER_CONTEXT=|WISEACCT_FASTAPI_DEV_ENV_FILE=|AUTH_DB_[A-Z0-9_]*=|DATABASE_URL=|REDIS_URL=|PORT=)'; then
  echo "Clear ambient Compose/Docker/SSO/libpq overrides before Phase 4" >&2
  exit 2
fi

command -v flock >/dev/null
readonly LOCK_FILE="$(git -C "${REPO_DIR}" rev-parse --git-common-dir)/wiseacct-phase4-integration.lock"
exec 9>"${LOCK_FILE}"
if ! flock --nonblock 9; then
  echo "Another Phase 4 integration run already owns the repository lock" >&2
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
  "${EVIDENCE_DIR}/phase4-junit.xml" \
  "${EVIDENCE_DIR}/phase4-pytest.txt" \
  "${EVIDENCE_DIR}/provenance.txt"
cat >"${EVIDENCE_DIR}/result.md" <<'EOF'
# Phase 4 provisional isolated integration result

- Guarded real PostgreSQL/Redis lane: RUNNING
- Overall Phase 4: **NOT COMPLETE**

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
    while IFS= read -r key; do
      [ -z "${key}" ] || docker exec wiseacct-sso-fastapi-dev-redis redis-cli -n 15 DEL "${key}" >/dev/null
    done < <(docker exec wiseacct-sso-fastapi-dev-redis redis-cli -n 15 --scan --pattern "${REDIS_PREFIX}*")
    "${SCRIPT_DIR}/dev-compose.sh" down "${ENV_FILE}" >/dev/null
  fi

  snapshot_express "${EVIDENCE_DIR}/express-after.txt"
  if ! cmp -s "${EVIDENCE_DIR}/express-before.txt" "${EVIDENCE_DIR}/express-after.txt"; then
    echo "Express runtime identity/health/restart snapshot changed" >&2
    cleanup_status=1
  fi
  if docker ps -a --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
    --format '{{.Names}}' | grep -q .; then
    echo "Candidate Compose containers remain after cleanup" >&2
    cleanup_status=1
  fi
  if docker network ls --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
    --format '{{.Name}}' | grep -q .; then
    echo "Candidate Compose network remains after cleanup" >&2
    cleanup_status=1
  fi
  if docker volume ls --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
    --format '{{.Name}}' | grep -q .; then
    echo "Candidate Compose volume remains after cleanup" >&2
    cleanup_status=1
  fi

  if (( original_status == 0 && cleanup_status == 0 )); then
    cat >"${EVIDENCE_DIR}/result.md" <<'EOF'
# Phase 4 provisional isolated integration result

- Guarded real PostgreSQL/Redis lane: PASS
- Overall Phase 4: **NOT COMPLETE**
- Scope: synthetic PostgreSQL `_test_` database on `127.0.0.1:5433` and Redis DB 15 on `127.0.0.1:6380`
- Schema owner: checked-in Prisma migrations; Python runtime role received DML only and DDL was denied with SQLSTATE `42501`
- Auth proofs: normalized registration, Node↔Python JWT/Argon2 and Zod-oracle compatibility, hashed-only refresh persistence, access-token `/users/me`, 20-way refresh single success, deterministic refresh/status mutation schedules, logout 204, exact five-failure/15-minute lock, Redis rate count/TTL/429, audit order/secret absence, and black-box TCP login→me→refresh→logout
- Source/image correlation: `provenance.txt`
- Cleanup: exact test database, DML role, Phase 4 Redis prefix, Compose containers/network/volume removed
- Express: container IDs, start times, restart counts, health states, and HTTP 200 unchanged
- Deferred: Express↔FastAPI mixed-writer refresh/logout and account-status schedules, production data/credentials, canonical refreeze/replay, and cutover

This evidence is PROVISIONAL and is not production replacement or cutover approval.
EOF
    echo "Phase 4 provisional integration gate passed"
    exit 0
  fi
  cat >"${EVIDENCE_DIR}/result.md" <<'EOF'
# Phase 4 provisional isolated integration result

- Guarded real PostgreSQL/Redis lane: FAIL
- Overall Phase 4: **NOT COMPLETE**
- Cleanup was attempted for the exact synthetic database, role, Redis namespace, and guarded Compose resources.
- Production data, credentials, routing, and cutover were never in scope.

This evidence is PROVISIONAL and is not production replacement or cutover approval.
EOF
  exit "$(( original_status == 0 ? 1 : original_status ))"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

command -v docker >/dev/null
command -v npm >/dev/null
command -v uv >/dev/null
snapshot_express "${EVIDENCE_DIR}/express-before.txt"

if docker ps -a --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
  --format '{{.Names}}' | grep -q . \
  || docker network ls --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
    --format '{{.Name}}' | grep -q . \
  || docker volume ls --filter label=com.docker.compose.project=wiseacct-sso-fastapi-dev \
    --format '{{.Name}}' | grep -q .; then
  echo "Phase 4 requires zero pre-existing candidate Compose resources" >&2
  exit 3
fi
python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 4011)); s.close()'

"${SCRIPT_DIR}/dev-compose.sh" up "${ENV_FILE}"
stack_started=1

source_tree_sha256="$(
  find "${FASTAPI_DIR}/src" -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    | sha256sum \
    | cut -d' ' -f1
)"
image_id="$(docker inspect --format '{{.Image}}' wiseacct-sso-fastapi-dev-app)"
git_head="$(git -C "${REPO_DIR}" rev-parse HEAD)"
printf 'gitHead=%s\nsourceTreeSha256=%s\nimageId=%s\n' \
  "${git_head}" "${source_tree_sha256}" "${image_id}" \
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
  WISEACCT_PHASE4_INTEGRATION=1 \
  WISEACCT_PHASE4_DATABASE_URL="${RUNTIME_URL}" \
  WISEACCT_PHASE4_REDIS_URL="${REDIS_URL}" \
  WISEACCT_PHASE4_RUN_ID="${RUN_ID}" \
  WISEACCT_PHASE4_HTTP_PORT="${HTTP_PORT}" \
  WISEACCT_EXPRESS_ARGON2_MODULE="${REPO_DIR}/auth-server/node_modules/argon2/argon2.cjs" \
  uv run --frozen pytest -vv --junitxml="${EVIDENCE_DIR}/phase4-junit.xml" \
    tests/integration/test_phase4_auth_runtime.py \
    tests/integration/test_phase4_blackbox_runtime.py \
    tests/integration/test_phase4_jwt_interop.py \
    tests/integration/test_argon2_compatibility.py \
    tests/unit/test_zod_url_oracle.py \
    | tee "${EVIDENCE_DIR}/phase4-pytest.txt"
)

test_count="$(python3 -c 'import sys, xml.etree.ElementTree as ET; print(len(ET.parse(sys.argv[1]).findall(".//testcase")))' "${EVIDENCE_DIR}/phase4-junit.xml")"
printf 'testsCollected=%s\n' "${test_count}" >>"${EVIDENCE_DIR}/provenance.txt"

if docker exec wiseacct-sso-fastapi-dev-redis redis-cli -n 15 --scan --pattern "${REDIS_PREFIX}*" \
  | grep -q .; then
  echo "Phase 4 Redis integration keys remain after the suite" >&2
  exit 5
fi
