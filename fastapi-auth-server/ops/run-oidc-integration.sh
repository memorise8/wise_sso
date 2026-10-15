#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly PYTHON="${FASTAPI_DIR}/.venv/bin/python"
readonly RUN_ID="$(date -u +%Y%m%d%H%M%S)_$$_${RANDOM}"
readonly SAFE_RUN_ID="${RUN_ID//[^A-Za-z0-9_]/_}"
readonly LABEL="wiseacct.oidc.integration.run=${SAFE_RUN_ID}"
readonly PG_NAME="wiseacct-oidc-test-pg-${SAFE_RUN_ID}"
readonly REDIS_NAME="wiseacct-oidc-test-redis-${SAFE_RUN_ID}"
readonly DATABASE_NAME="wiseacct_oidc_test_${SAFE_RUN_ID}"
readonly ADMIN_USER="oidc_migration_${SAFE_RUN_ID}"
readonly ADMIN_PASSWORD="synthetic-oidc-migration-only"
readonly RUNTIME_USER="oidc_runtime_${SAFE_RUN_ID}"
readonly RUNTIME_PASSWORD="synthetic-oidc-runtime-only"

if env | grep -Eq '^(PG[A-Z0-9_]*=|COMPOSE_|DOCKER_HOST=|DOCKER_CONTEXT=|DATABASE_URL=|REDIS_URL=|PORT=|WISEACCT_OIDC_RUNTIME_[A-Z0-9_]*=)'; then
  echo "Clear ambient Docker/SSO/libpq overrides before the OIDC integration run" >&2
  exit 2
fi

command -v docker >/dev/null
test -x "${PYTHON}"
docker image inspect postgres:17-alpine >/dev/null
docker image inspect redis:7-alpine >/dev/null

readonly GIT_COMMON_DIR="$(git -C "${REPO_DIR}" rev-parse --git-common-dir)"
exec 8>"${GIT_COMMON_DIR}/wiseacct-oidc-integration.lock"
if ! flock --nonblock 8; then
  echo "Another guarded OIDC integration run owns the repository lock" >&2
  exit 4
fi

pg_id=""
redis_id=""
cleanup_status=0

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  set +e
  if [[ -n "${pg_id}" ]]; then
    docker rm --force "${pg_id}" >/dev/null 2>&1 || cleanup_status=1
  fi
  if [[ -n "${redis_id}" ]]; then
    docker rm --force "${redis_id}" >/dev/null 2>&1 || cleanup_status=1
  fi
  if docker ps -a --filter "label=${LABEL}" --format '{{.ID}}' | grep -q .; then
    echo "OIDC integration containers remain after cleanup" >&2
    cleanup_status=1
  fi
  if (( original_status == 0 && cleanup_status == 0 )); then
    echo "OIDC isolated runtime integration passed; exact temporary containers removed"
    exit 0
  fi
  echo "OIDC isolated runtime integration failed; exact-container cleanup attempted" >&2
  exit "$(( original_status == 0 ? 1 : original_status ))"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

pg_id="$(docker run --detach --pull=never \
  --name "${PG_NAME}" \
  --label "${LABEL}" \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev \
  --publish 127.0.0.1::5432 \
  --env "POSTGRES_DB=${DATABASE_NAME}" \
  --env "POSTGRES_USER=${ADMIN_USER}" \
  --env "POSTGRES_PASSWORD=${ADMIN_PASSWORD}" \
  postgres:17-alpine)"
redis_id="$(docker run --detach --pull=never \
  --name "${REDIS_NAME}" \
  --label "${LABEL}" \
  --tmpfs /data:rw,noexec,nosuid,nodev \
  --publish 127.0.0.1::6379 \
  redis:7-alpine redis-server --save '' --appendonly no)"

for _ in $(seq 1 100); do
  if docker exec "${pg_id}" pg_isready --username "${ADMIN_USER}" --dbname "${DATABASE_NAME}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
# The official image briefly exposes its bootstrap postmaster before replacing it
# with the final server. Do not feed a migration into that restart window.
sleep 0.5
docker exec "${pg_id}" pg_isready --username "${ADMIN_USER}" --dbname "${DATABASE_NAME}" >/dev/null

for _ in $(seq 1 100); do
  if docker exec "${redis_id}" redis-cli -n 15 ping 2>/dev/null | grep -qx PONG; then
    break
  fi
  sleep 0.05
done
docker exec "${redis_id}" redis-cli -n 15 ping | grep -qx PONG
if [[ "$(docker exec "${redis_id}" redis-cli -n 15 dbsize)" != "0" ]]; then
  echo "Fresh OIDC Redis DB 15 is not empty" >&2
  exit 5
fi

while IFS= read -r migration; do
  docker exec --interactive "${pg_id}" \
    psql --username "${ADMIN_USER}" --dbname "${DATABASE_NAME}" --set ON_ERROR_STOP=1 \
    <"${migration}" >/dev/null
done < <(find "${REPO_DIR}/auth-server/prisma/migrations" -mindepth 2 -maxdepth 2 \
  -type f -name migration.sql -print | sort)

docker exec "${pg_id}" psql --username "${ADMIN_USER}" --dbname "${DATABASE_NAME}" \
  --set ON_ERROR_STOP=1 --command="CREATE ROLE \"${RUNTIME_USER}\" LOGIN PASSWORD '${RUNTIME_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT; REVOKE CREATE ON SCHEMA public FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM \"${RUNTIME_USER}\"; GRANT CONNECT ON DATABASE \"${DATABASE_NAME}\" TO \"${RUNTIME_USER}\"; GRANT USAGE ON SCHEMA public TO \"${RUNTIME_USER}\"; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"${RUNTIME_USER}\";" \
  >/dev/null

readonly PG_PORT="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "${pg_id}")"
readonly REDIS_PORT="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "6379/tcp") 0).HostPort}}' "${redis_id}")"
readonly HTTP_PORT="$(${PYTHON} -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

for port in "${PG_PORT}" "${REDIS_PORT}" "${HTTP_PORT}"; do
  if [[ ! "${port}" =~ ^[0-9]+$ ]] || (( port < 10000 )) || [[ "${port}" =~ ^(4000|4001|5432|5433|6379|6380)$ ]]; then
    echo "Docker assigned an unsafe integration port" >&2
    exit 6
  fi
done
if [[ "${PG_PORT}" == "${REDIS_PORT}" || "${PG_PORT}" == "${HTTP_PORT}" || "${REDIS_PORT}" == "${HTTP_PORT}" ]]; then
  echo "OIDC integration ports must be unique" >&2
  exit 6
fi

cd "${FASTAPI_DIR}"
env -i \
  PATH="${PATH}" \
  WISEACCT_OIDC_RUNTIME_INTEGRATION=1 \
  WISEACCT_OIDC_RUNTIME_DATABASE_URL="postgresql+asyncpg://${RUNTIME_USER}:${RUNTIME_PASSWORD}@127.0.0.1:${PG_PORT}/${DATABASE_NAME}" \
  WISEACCT_OIDC_RUNTIME_REDIS_URL="redis://127.0.0.1:${REDIS_PORT}/15" \
  WISEACCT_OIDC_RUNTIME_HTTP_PORT="${HTTP_PORT}" \
  WISEACCT_OIDC_RUNTIME_RUN_ID="${SAFE_RUN_ID}" \
  "${PYTHON}" -m pytest -vv tests/integration/test_oidc_runtime.py

# This is a newly created, single-run Redis container and DB 15 is its only test
# namespace. Remove still-live five-minute bearer records before final disposal.
docker exec "${redis_id}" redis-cli -n 15 flushdb | grep -qx OK
if [[ "$(docker exec "${redis_id}" redis-cli -n 15 dbsize)" != "0" ]]; then
  echo "OIDC Redis DB 15 retained keys after runtime shutdown" >&2
  exit 7
fi
