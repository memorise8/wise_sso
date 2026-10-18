#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_DIR="$(cd -- "${FASTAPI_DIR}/.." && pwd)"
readonly ENV_FILE="${FASTAPI_DIR}/.env.example"
readonly PG_CONTAINER="wiseacct-sso-fastapi-dev-postgres"
readonly REDIS_CONTAINER="wiseacct-sso-fastapi-dev-redis"
readonly EXPRESS_CONTAINERS=(auth-server-app-1 auth-server-postgres-1 auth-server-redis-1)
readonly EVIDENCE_DIR="${FASTAPI_DIR}/evidence/phase2"
readonly RUN_ID="$(date -u +%Y%m%d%H%M%S)-$$"
readonly TEST_DATABASE="fastapi_phase2_test_${RUN_ID//-/_}"
readonly RESTORE_DATABASE="fastapi_phase2_restore_test_${RUN_ID//-/_}"
readonly RUNTIME_ROLE="phase2_runtime_${RUN_ID//-/_}"
readonly RUNTIME_PASSWORD="synthetic-phase2-runtime-only"
readonly ADMIN_URL="postgresql://fastapi_dev:synthetic-fastapi-db-only@127.0.0.1:5433/${TEST_DATABASE}"
readonly RUNTIME_URL="postgresql+asyncpg://${RUNTIME_ROLE}:${RUNTIME_PASSWORD}@127.0.0.1:5433/${TEST_DATABASE}"
readonly PRISMA_RUNTIME_URL="postgresql://${RUNTIME_ROLE}:${RUNTIME_PASSWORD}@127.0.0.1:5433/${TEST_DATABASE}"
readonly REDIS_PREFIX="wiseacct:phase2:${RUN_ID}:"
readonly REDIS_TEST_PREFIX="wiseacct:test:fastapi:redis-primitives:"
readonly BACKUP_FILE="${EVIDENCE_DIR}/synthetic-phase2.dump"

# Reject every ambient libpq connection/control variable. Host PostgreSQL tools below
# receive only PATH and the one synthetic password required for that exact invocation.
if env | grep -Eq '^(PG[A-Z0-9_]*=|COMPOSE_|DOCKER_HOST=|DOCKER_CONTEXT=|WISEACCT_FASTAPI_DEV_ENV_FILE=|AUTH_DB_[A-Z0-9_]*=|DATABASE_URL=|REDIS_URL=|PORT=)'; then
  echo "Clear ambient Compose/Docker/SSO/libpq PG* overrides before Phase 2" >&2
  exit 2
fi

stack_started=0
database_created=0
restore_database_created=0
cleanup_status=0

mkdir -p "${EVIDENCE_DIR}"
rm -f \
  "${EVIDENCE_DIR}/express-after.txt" \
  "${EVIDENCE_DIR}/postgres-junit.xml" \
  "${EVIDENCE_DIR}/postgres-pytest.txt" \
  "${EVIDENCE_DIR}/prisma-semantics.json" \
  "${EVIDENCE_DIR}/redis-junit.xml" \
  "${EVIDENCE_DIR}/redis-pytest.txt" \
  "${EVIDENCE_DIR}/synthetic-backup-restore.json"
cat >"${EVIDENCE_DIR}/result.md" <<'EOF'
# Phase 2 provisional isolated integration result

- Isolated synthetic subset: RUNNING
- Overall Phase 2: **NOT COMPLETE**

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
  if (( restore_database_created == 1 )); then
    postgres_admin --command="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${RESTORE_DATABASE}' AND pid <> pg_backend_pid();" >/dev/null
    postgres_admin --command="DROP DATABASE IF EXISTS \"${RESTORE_DATABASE}\";" >/dev/null
  fi
  if (( database_created == 1 )); then
    postgres_admin --command="DROP ROLE IF EXISTS \"${RUNTIME_ROLE}\";" >/dev/null
  fi
  [ ! -e "${BACKUP_FILE}" ] || rm -- "${BACKUP_FILE}"

  if (( stack_started == 1 )); then
    while IFS= read -r key; do
      [ -z "${key}" ] || docker exec "${REDIS_CONTAINER}" redis-cli DEL "${key}" >/dev/null
    done < <(docker exec "${REDIS_CONTAINER}" redis-cli --scan --pattern "${REDIS_PREFIX}*")
    while IFS= read -r key; do
      [ -z "${key}" ] || docker exec "${REDIS_CONTAINER}" redis-cli DEL "${key}" >/dev/null
    done < <(docker exec "${REDIS_CONTAINER}" redis-cli --scan --pattern "${REDIS_TEST_PREFIX}*")
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
# Phase 2 provisional isolated integration result

- Isolated synthetic subset: PASS
- Overall Phase 2: **NOT COMPLETE**
- Scope: synthetic PostgreSQL database with `_test_` in its name on `127.0.0.1:5433`
- Prisma owner: checked-in migrations applied with `prisma migrate deploy`
- Runtime role: DML-only; `CREATE TABLE` denied with SQLSTATE `42501`
- Live DB proofs: catalog mirror, Prisma semantic oracle including exact TIMESTAMP(3) roundtrip, failed-login 4/5/20 concurrency, refresh 20-way single-success, and Argon2 Node/Python interoperability
- Live Redis proofs: NX+EX, exact-value consume, rate-limit count/TTL, consume races, and fail-closed unavailable endpoint
- Backup proof: synthetic-only custom-format dump, disposable `_test_` restore, and read-only application-role smoke
- Cleanup: exact test database, runtime role, Phase 2 Redis prefix, Compose containers/network/volume removed
- Express: container IDs, start times, restart counts, health states, and HTTP 200 unchanged
- Deferred: all remaining transaction-map flows, real production backup restore, shared Express/FastAPI runtime, production data/credentials, and production-like mixed-writer interleavings

This evidence is PROVISIONAL and is not production replacement or cutover approval.
EOF
    echo "Phase 2 provisional integration gate passed"
    exit 0
  fi
  cat >"${EVIDENCE_DIR}/result.md" <<'EOF'
# Phase 2 provisional isolated integration result

- Isolated synthetic subset: FAIL
- Overall Phase 2: **NOT COMPLETE**
- Cleanup was attempted for the exact synthetic database, role, Redis namespace, and guarded Compose resources.
- Real production backup restore, shared runtime, production data, credentials, and cutover were never in scope.

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

"${SCRIPT_DIR}/dev-compose.sh" up "${ENV_FILE}"
stack_started=1

postgres_admin --command="CREATE DATABASE \"${TEST_DATABASE}\" OWNER fastapi_dev;"
database_created=1

(
  cd "${REPO_DIR}/auth-server"
  npm ci --no-audit --no-fund
  DATABASE_URL="${ADMIN_URL}" npx prisma migrate deploy
)

postgres_admin --command="CREATE ROLE \"${RUNTIME_ROLE}\" LOGIN PASSWORD '${RUNTIME_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;"
docker exec "${PG_CONTAINER}" psql --username fastapi_dev --dbname "${TEST_DATABASE}" \
  --set ON_ERROR_STOP=1 --command="REVOKE CREATE ON SCHEMA public FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM \"${RUNTIME_ROLE}\"; GRANT CONNECT ON DATABASE \"${TEST_DATABASE}\" TO \"${RUNTIME_ROLE}\"; GRANT USAGE ON SCHEMA public TO \"${RUNTIME_ROLE}\"; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"${RUNTIME_ROLE}\";"

(
  cd "${REPO_DIR}/auth-server"
  PHASE2_DATABASE_URL="${PRISMA_RUNTIME_URL}" node scripts/phase2-prisma-oracle.mjs \
    >"${EVIDENCE_DIR}/prisma-semantics.json"
)

docker exec "${PG_CONTAINER}" psql --username fastapi_dev --dbname "${TEST_DATABASE}" \
  --set ON_ERROR_STOP=1 --command="INSERT INTO \"SubjectReservation\" (id, email, \"subjectId\", reason, \"createdAt\", \"updatedAt\") VALUES ('phase2-synthetic-backup-fixture', 'phase2-backup@integration.invalid', 'phase2-synthetic-backup-subject', 'synthetic-only', TIMESTAMP '2026-01-02 03:04:05.123', TIMESTAMP '2026-01-02 03:04:05.123');"
env -i PATH="${PATH}" PGPASSWORD="synthetic-fastapi-db-only" pg_dump \
  --host 127.0.0.1 --port 5433 --username fastapi_dev --dbname "${TEST_DATABASE}" \
  --format custom --no-owner --no-acl --file "${BACKUP_FILE}"
postgres_admin --command="CREATE DATABASE \"${RESTORE_DATABASE}\" OWNER fastapi_dev;"
restore_database_created=1
env -i PATH="${PATH}" PGPASSWORD="synthetic-fastapi-db-only" pg_restore \
  --host 127.0.0.1 --port 5433 --username fastapi_dev --dbname "${RESTORE_DATABASE}" \
  --clean --if-exists --no-owner --no-acl "${BACKUP_FILE}"
docker exec "${PG_CONTAINER}" psql --username fastapi_dev --dbname "${RESTORE_DATABASE}" \
  --set ON_ERROR_STOP=1 --command="REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT CONNECT ON DATABASE \"${RESTORE_DATABASE}\" TO \"${RUNTIME_ROLE}\"; GRANT USAGE ON SCHEMA public TO \"${RUNTIME_ROLE}\"; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"${RUNTIME_ROLE}\";"
env -i PATH="${PATH}" PGPASSWORD="${RUNTIME_PASSWORD}" psql \
  --host 127.0.0.1 --port 5433 --username "${RUNTIME_ROLE}" --dbname "${RESTORE_DATABASE}" \
  --set ON_ERROR_STOP=1 --tuples-only \
  --command="BEGIN READ ONLY; SELECT count(*) FROM \"SubjectReservation\" WHERE id = 'phase2-synthetic-backup-fixture'; COMMIT;" \
  | tr -d '[:space:]' | grep -qx 'BEGIN1COMMIT'
printf '%s\n' '{"provisional":true,"source":"synthetic-only","format":"custom","restoreDatabaseContains":"_test_","readOnlySmoke":"pass","productionBackup":"deferred"}' \
  >"${EVIDENCE_DIR}/synthetic-backup-restore.json"
rm -- "${BACKUP_FILE}"

(
  cd "${FASTAPI_DIR}"
  WISEACCT_PHASE2_INTEGRATION=1 \
  WISEACCT_PHASE2_DATABASE_URL="${RUNTIME_URL}" \
  WISEACCT_PHASE2_PRISMA_EVIDENCE_FILE="${EVIDENCE_DIR}/prisma-semantics.json" \
  WISEACCT_EXPRESS_ARGON2_MODULE="${REPO_DIR}/auth-server/node_modules/argon2/argon2.cjs" \
  uv run --frozen pytest -vv --junitxml="${EVIDENCE_DIR}/postgres-junit.xml" \
    tests/integration/test_postgres_phase2.py \
    tests/integration/test_argon2_compatibility.py \
    | tee "${EVIDENCE_DIR}/postgres-pytest.txt"
)

(
  cd "${FASTAPI_DIR}"
  WISEACCT_FASTAPI_TEST_REDIS_URL="redis://127.0.0.1:6380/15" \
  WISEACCT_FASTAPI_TEST_REDIS_CONTAINER="${REDIS_CONTAINER}" \
  uv run --frozen pytest -vv --junitxml="${EVIDENCE_DIR}/redis-junit.xml" \
    tests/integration/test_redis_primitives.py \
    | tee "${EVIDENCE_DIR}/redis-pytest.txt"
)

if docker exec "${REDIS_CONTAINER}" redis-cli --scan --pattern "${REDIS_TEST_PREFIX}*" \
  | grep -q .; then
  echo "Phase 2 Redis integration keys remain after the suite" >&2
  exit 5
fi
