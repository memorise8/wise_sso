#!/usr/bin/env bash
set -euo pipefail

readonly POSTGRES_CONTAINER="wiseacct-phase0-postgres"
readonly REDIS_CONTAINER="wiseacct-phase0-redis"
readonly POSTGRES_PORT="5433"
readonly REDIS_PORT="6380"
readonly POSTGRES_PASSWORD="phase0-disposable-only"
readonly PHASE0_TEST_DATABASE_URL="postgresql://postgres:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/auth_db"
readonly PHASE0_TEST_REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"
postgres_started=0
redis_started=0

cleanup() {
  if (( redis_started == 1 )); then
    docker rm -f "${REDIS_CONTAINER}" >/dev/null 2>&1 || true
  fi
  if (( postgres_started == 1 )); then
    docker rm -f "${POSTGRES_CONTAINER}" >/dev/null 2>&1 || true
  fi
}

refuse_existing_container() {
  local container_name="$1"
  if docker container inspect "${container_name}" >/dev/null 2>&1; then
    echo "Refusing to replace existing container: ${container_name}" >&2
    exit 1
  fi
}

refuse_occupied_port() {
  local port="$1"
  if ss -ltnH "sport = :${port}" | grep -q .; then
    echo "Refusing to use occupied localhost port: ${port}" >&2
    exit 1
  fi
}

wait_for_postgres() {
  local attempt
  for attempt in $(seq 1 60); do
    if docker exec "${POSTGRES_CONTAINER}" pg_isready -U postgres -d auth_db >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "Disposable PostgreSQL did not become ready" >&2
  return 1
}

wait_for_redis() {
  local attempt
  for attempt in $(seq 1 60); do
    if docker exec "${REDIS_CONTAINER}" redis-cli ping 2>/dev/null | grep -qx PONG; then
      return
    fi
    sleep 1
  done
  echo "Disposable Redis did not become ready" >&2
  return 1
}

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
command -v ss >/dev/null 2>&1 || { echo "ss is required" >&2; exit 1; }
docker info >/dev/null

refuse_existing_container "${POSTGRES_CONTAINER}"
refuse_existing_container "${REDIS_CONTAINER}"
refuse_occupied_port "${POSTGRES_PORT}"
refuse_occupied_port "${REDIS_PORT}"

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker run --rm --detach \
  --name "${POSTGRES_CONTAINER}" \
  --publish "127.0.0.1:${POSTGRES_PORT}:5432" \
  --env POSTGRES_DB=auth_db \
  --env POSTGRES_USER=postgres \
  --env "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}" \
  postgres:16-alpine >/dev/null
postgres_started=1

docker run --rm --detach \
  --name "${REDIS_CONTAINER}" \
  --publish "127.0.0.1:${REDIS_PORT}:6379" \
  redis:7.4-alpine redis-server --appendonly no >/dev/null
redis_started=1

wait_for_postgres
wait_for_redis

DATABASE_URL="${PHASE0_TEST_DATABASE_URL}" npx prisma migrate deploy

PHASE0_INTEGRATION=1 \
PHASE0_DATABASE_URL="${PHASE0_TEST_DATABASE_URL}" \
PHASE0_REDIS_URL="${PHASE0_TEST_REDIS_URL}" \
npx vitest run src/services/phase0-concurrency.integration.test.ts
