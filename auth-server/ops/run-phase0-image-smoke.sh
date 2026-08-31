#!/usr/bin/env bash
set -euo pipefail

readonly APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_DIR="$(cd "${APP_DIR}/.." && pwd)"
readonly EVIDENCE_DIR="${REPO_DIR}/contracts/evidence"
readonly EVIDENCE_FILE="${EVIDENCE_DIR}/phase0-image-smoke.txt"
readonly DIAGNOSTICS_FILE="${EVIDENCE_DIR}/phase0-image-smoke-diagnostics.txt"
readonly NETWORK_NAME="wiseacct-phase0-smoke-net"
readonly POSTGRES_CONTAINER="wiseacct-phase0-smoke-pg"
readonly REDIS_CONTAINER="wiseacct-phase0-smoke-redis"
readonly APP_CONTAINER="wiseacct-phase0-smoke-app"
readonly POSTGRES_IMAGE="postgres:16-alpine"
readonly REDIS_IMAGE="redis:7.4-alpine"
readonly POSTGRES_PORT="5433"
readonly APP_PORT="4001"
readonly OWNERSHIP_LABEL="wiseacct.phase0-smoke.run-id"
readonly INPUTS_LABEL="com.wiseacct.sso.source-inputs-sha256"
readonly CANDIDATE_IMAGE="${1:-${PHASE0_CANDIDATE_IMAGE:-}}"
readonly -a BUILD_INPUTS=(
  auth-server/Dockerfile
  auth-server/package.json
  auth-server/package-lock.json
  auth-server/tsconfig.json
  auth-server/prisma
  auth-server/src
  auth-server/public
)

evidence_temp=""
temp_dir=""
run_id=""
network_id=""
postgres_container_id=""
redis_container_id=""
app_container_id=""
postgres_password=""
postgres_proxy_pid=""
app_proxy_pid=""
last_proxy_pid=""

log() {
  printf '%s\n' "$1" | tee -a "${evidence_temp}"
}

validate_artifact_destination() {
  local artifact_file="$1"
  [[ ! -L "${artifact_file}" ]] || return 1
  if [[ -e "${artifact_file}" ]]; then
    [[ -f "${artifact_file}" && "$(stat -c '%h' "${artifact_file}")" == "1" ]] || return 1
  fi
}

atomic_write_diagnostic_marker() {
  local marker_file
  marker_file="$(mktemp "${EVIDENCE_DIR}/.phase0-image-smoke-diagnostics.XXXXXX")"
  chmod 600 "${marker_file}"
  printf 'EMPTY latest-smoke-result=PASS\n' >"${marker_file}"
  mv -f -- "${marker_file}" "${DIAGNOSTICS_FILE}"
}

capture_failure_diagnostics() {
  local raw_file="${temp_dir}/diagnostics.raw"
  local sanitized_file
  local log_file
  : >"${raw_file}"

  for log_file in \
    network-launch.log postgres-launch.log redis-launch.log \
    postgres-proxy.log prisma-format.log prisma.log docker-app.log app-proxy.log jwks-curl.log; do
    printf '\n== %s ==\n' "${log_file}" >>"${raw_file}"
    if [[ -f "${temp_dir}/${log_file}" ]]; then
      tail -n 80 "${temp_dir}/${log_file}" >>"${raw_file}" 2>/dev/null || true
    else
      printf 'not-created\n' >>"${raw_file}"
    fi
  done

  for container_entry in \
    "candidate:${app_container_id}" \
    "postgres:${postgres_container_id}" \
    "redis:${redis_container_id}"; do
    local container_role="${container_entry%%:*}"
    local container_id="${container_entry#*:}"
    printf '\n== %s-container-state ==\n' "${container_role}" >>"${raw_file}"
    if [[ -n "${container_id}" ]] && docker container inspect "${container_id}" >/dev/null 2>&1; then
      docker container inspect --format \
        'id={{.Id}} image={{.Image}} status={{.State.Status}} running={{.State.Running}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' \
        "${container_id}" >>"${raw_file}" 2>/dev/null || true
      printf '\n== %s-container-log-tail ==\n' "${container_role}" >>"${raw_file}"
      docker logs --tail 80 "${container_id}" >>"${raw_file}" 2>&1 || true
    else
      printf 'not-created-or-already-removed\n' >>"${raw_file}"
    fi
  done

  sanitized_file="$(mktemp "${EVIDENCE_DIR}/.phase0-image-smoke-diagnostics.XXXXXX")"
  chmod 600 "${sanitized_file}"
  PHASE0_POSTGRES_PASSWORD="${postgres_password}" \
  PHASE0_DIAGNOSTICS_RAW_FILE="${raw_file}" \
  PHASE0_DIAGNOSTICS_OUTPUT_FILE="${sanitized_file}" \
  node --input-type=module <<'NODE'
import { readFileSync, writeFileSync } from "node:fs";

let text = readFileSync(process.env.PHASE0_DIAGNOSTICS_RAW_FILE, "utf8");
const exactSecrets = [process.env.PHASE0_POSTGRES_PASSWORD].filter((value) => value?.length);
for (const secret of exactSecrets) text = text.split(secret).join("[REDACTED]");
text = text
  .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]")
  .replace(/(postgres(?:ql)?:\/\/[^:\s/]+:)[^@\s/]+@/gi, "$1[REDACTED]@")
  .replace(/\b(authorization|cookie|password|secret|token|api[_-]?key)(\s*[:=]\s*)([^\s,;]+)/gi, "$1$2[REDACTED]")
  .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED_JWT]");
writeFileSync(process.env.PHASE0_DIAGNOSTICS_OUTPUT_FILE, text, { mode: 0o600 });
NODE
  mv -f -- "${sanitized_file}" "${DIAGNOSTICS_FILE}"
}

fail() {
  log "ERROR: $1" >&2
  exit 1
}

container_is_owned() {
  local container_id="$1"
  local expected_id="$2"
  local identity
  identity="$(docker container inspect --format "{{.Id}} {{index .Config.Labels \"${OWNERSHIP_LABEL}\"}}" "${container_id}" 2>/dev/null || true)"
  [[ "${identity}" == "${expected_id} ${run_id}" ]]
}

network_is_owned() {
  local identity
  identity="$(docker network inspect --format "{{.Id}} {{index .Labels \"${OWNERSHIP_LABEL}\"}}" "${network_id}" 2>/dev/null || true)"
  [[ "${identity}" == "${network_id} ${run_id}" ]]
}

remove_owned_container() {
  local container_id="$1"
  [[ -z "${container_id}" ]] && return 0
  if ! docker container inspect "${container_id}" >/dev/null 2>&1; then
    return 0
  fi
  if ! container_is_owned "${container_id}" "${container_id}"; then
    return 1
  fi
  docker rm -f "${container_id}" >/dev/null 2>&1
}

proxy_is_owned() {
  local proxy_pid="$1"
  [[ -r "/proc/${proxy_pid}/environ" ]] \
    && grep -zFqx "PHASE0_SMOKE_RUN_ID=${run_id}" "/proc/${proxy_pid}/environ"
}

stop_owned_proxy() {
  local proxy_pid="$1"
  [[ -z "${proxy_pid}" ]] && return 0
  if ! kill -0 "${proxy_pid}" 2>/dev/null; then
    return 0
  fi
  proxy_is_owned "${proxy_pid}" || return 1
  kill "${proxy_pid}" 2>/dev/null || return 1
  wait "${proxy_pid}" 2>/dev/null || true
  ! kill -0 "${proxy_pid}" 2>/dev/null
}

start_loopback_proxy() {
  local listen_port="$1"
  local target_host="$2"
  local target_port="$3"
  local log_file="$4"
  local ready_file="${log_file}.ready"
  local attempt

  PHASE0_SMOKE_RUN_ID="${run_id}" \
  PHASE0_PROXY_LISTEN_PORT="${listen_port}" \
  PHASE0_PROXY_TARGET_HOST="${target_host}" \
  PHASE0_PROXY_TARGET_PORT="${target_port}" \
  PHASE0_PROXY_READY_FILE="${ready_file}" \
  node --input-type=module >"${log_file}" 2>&1 <<'NODE' &
import { createConnection, createServer } from "node:net";
import { writeFileSync } from "node:fs";

const server = createServer((inbound) => {
  const outbound = createConnection({
    host: process.env.PHASE0_PROXY_TARGET_HOST,
    port: Number(process.env.PHASE0_PROXY_TARGET_PORT)
  });
  inbound.on("error", () => outbound.destroy());
  outbound.on("error", () => inbound.destroy());
  inbound.pipe(outbound).pipe(inbound);
});
server.listen(Number(process.env.PHASE0_PROXY_LISTEN_PORT), "127.0.0.1", () => {
  writeFileSync(process.env.PHASE0_PROXY_READY_FILE, "ready\n", { mode: 0o600 });
});
NODE
  last_proxy_pid=$!

  for (( attempt = 1; attempt <= 30; attempt += 1 )); do
    if [[ -s "${ready_file}" ]]; then
      proxy_is_owned "${last_proxy_pid}" || return 1
      if ss -ltnpH "sport = :${listen_port}" | grep -Fq "pid=${last_proxy_pid},"; then
        return 0
      fi
      return 1
    fi
    kill -0 "${last_proxy_pid}" 2>/dev/null || return 1
    sleep 1
  done
  return 1
}

cleanup() {
  local exit_code=$?
  local cleanup_failed=0
  trap - EXIT INT TERM

  if (( exit_code != 0 )); then
    capture_failure_diagnostics || {
      exit_code=1
      log "diagnostics=failed-to-publish"
    }
  fi

  stop_owned_proxy "${app_proxy_pid}" || cleanup_failed=1
  stop_owned_proxy "${postgres_proxy_pid}" || cleanup_failed=1
  remove_owned_container "${app_container_id}" || cleanup_failed=1
  remove_owned_container "${redis_container_id}" || cleanup_failed=1
  remove_owned_container "${postgres_container_id}" || cleanup_failed=1
  if [[ -n "${network_id}" ]]; then
    if network_is_owned; then
      docker network rm "${network_id}" >/dev/null 2>&1 || cleanup_failed=1
    else
      cleanup_failed=1
    fi
  fi
  if (( cleanup_failed == 1 )); then
    exit_code=1
    log "cleanup=failed owned-resource-id-or-label-mismatch"
    capture_failure_diagnostics || log "diagnostics=failed-to-publish-cleanup-failure"
  elif (( exit_code == 0 )); then
    atomic_write_diagnostic_marker || {
      exit_code=1
      log "diagnostics=failed-to-clear-after-success"
      capture_failure_diagnostics || log "diagnostics=failed-to-publish-marker-failure"
    }
    log "cleanup=ok verified-owned-resources-removed"
  else
    log "cleanup=ok verified-owned-resources-removed-after-failure"
  fi
  if (( exit_code == 0 )); then
    log "result=PASS"
  else
    log "result=FAIL"
  fi

  if [[ -n "${temp_dir}" && -d "${temp_dir}" ]]; then
    rm -r -- "${temp_dir}"
  fi

  if ! mv -f -- "${evidence_temp}" "${EVIDENCE_FILE}"; then
    printf 'ERROR: could not atomically publish Phase 0 smoke evidence\n' >&2
    exit 1
  fi
  evidence_temp=""
  exit "${exit_code}"
}

refuse_existing_container() {
  local container_name="$1"
  if docker container inspect "${container_name}" >/dev/null 2>&1; then
    fail "refusing to replace existing disposable container ${container_name}"
  fi
}

refuse_existing_network() {
  if docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1; then
    fail "refusing to replace existing disposable network ${NETWORK_NAME}"
  fi
}

refuse_occupied_port() {
  local port="$1"
  if ss -ltnH "sport = :${port}" | grep -q .; then
    fail "refusing to use occupied loopback port ${port}"
  fi
}

wait_for_postgres() {
  local attempt
  for (( attempt = 1; attempt <= 60; attempt += 1 )); do
    if docker exec "${postgres_container_id}" pg_isready -U postgres -d auth_db >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  log "postgres-status=$(docker container inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}}' "${postgres_container_id}" 2>/dev/null || printf 'missing')"
  fail "disposable PostgreSQL did not become ready"
}

wait_for_redis() {
  local attempt
  for (( attempt = 1; attempt <= 60; attempt += 1 )); do
    if docker exec "${redis_container_id}" redis-cli ping 2>/dev/null | grep -qx PONG; then
      return 0
    fi
    sleep 1
  done
  log "redis-status=$(docker container inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}}' "${redis_container_id}" 2>/dev/null || printf 'missing')"
  fail "disposable Redis did not become ready"
}

app_status() {
  docker container inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}}' "${app_container_id}" 2>/dev/null \
    || printf 'status=missing exit=unknown'
}

wait_for_endpoint() {
  local endpoint="$1"
  local attempt
  for (( attempt = 1; attempt <= 90; attempt += 1 )); do
    if curl --fail --silent --show-error --max-time 2 \
      "http://127.0.0.1:${APP_PORT}${endpoint}" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$(docker container inspect --format '{{.State.Running}}' "${app_container_id}" 2>/dev/null || true)" != "true" ]]; then
      log "candidate-app-$(app_status)"
      fail "candidate app exited before ${endpoint} became ready"
    fi
    sleep 1
  done
  log "candidate-app-$(app_status)"
  fail "candidate app did not serve ${endpoint}"
}

for command_name in docker ss curl node tee git sha256sum mktemp stat readlink grep tail cp; do
  command -v "${command_name}" >/dev/null 2>&1 \
    || { printf 'ERROR: %s is required\n' "${command_name}" >&2; exit 1; }
done

[[ "$(readlink -f "${EVIDENCE_DIR}")" == "${EVIDENCE_DIR}" ]] \
  || { printf 'ERROR: evidence directory is not the canonical repository path\n' >&2; exit 1; }
validate_artifact_destination "${EVIDENCE_FILE}" \
  || { printf 'ERROR: evidence destination must be a regular single-link non-symlink file\n' >&2; exit 1; }
validate_artifact_destination "${DIAGNOSTICS_FILE}" \
  || { printf 'ERROR: diagnostics destination must be a regular single-link non-symlink file\n' >&2; exit 1; }
evidence_temp="$(mktemp "${EVIDENCE_DIR}/.phase0-image-smoke.XXXXXX")"
chmod 600 "${evidence_temp}"
temp_dir="$(mktemp -d)"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ -n "${CANDIDATE_IMAGE}" ]] || fail "candidate image argument is required"
[[ -x "${APP_DIR}/node_modules/.bin/prisma" ]] || fail "pinned local Prisma binary is not installed"
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
docker image inspect "${CANDIDATE_IMAGE}" >/dev/null 2>&1 || fail "candidate image does not exist locally"
docker image inspect "${POSTGRES_IMAGE}" >/dev/null 2>&1 || fail "pinned-major PostgreSQL image is not present locally"
docker image inspect "${REDIS_IMAGE}" >/dev/null 2>&1 || fail "pinned-minor Redis image is not present locally"

refuse_existing_network
refuse_existing_container "${POSTGRES_CONTAINER}"
refuse_existing_container "${REDIS_CONTAINER}"
refuse_existing_container "${APP_CONTAINER}"
refuse_occupied_port "${POSTGRES_PORT}"
refuse_occupied_port "${APP_PORT}"

run_id="$(node -e 'process.stdout.write(require("node:crypto").randomUUID())')"
postgres_password="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(48).toString("base64url"))')"
readonly source_sha="$(git -C "${REPO_DIR}" rev-parse --verify HEAD^{commit})"
readonly input_status="$(git -C "${REPO_DIR}" status --porcelain=v1 --untracked-files=all -- "${BUILD_INPUTS[@]}")"
[[ -z "${input_status}" ]] \
  || fail "candidate build inputs must have no tracked or untracked changes relative to HEAD"
readonly tree_listing="$(git -C "${REPO_DIR}" ls-tree -r HEAD -- "${BUILD_INPUTS[@]}")"
[[ -n "${tree_listing}" ]] || fail "candidate build inputs are missing from HEAD"
readonly source_inputs_hash_line="$(printf '%s\n' "${tree_listing}" | sha256sum)"
readonly source_inputs_sha256="${source_inputs_hash_line%% *}"
readonly dockerfile_sha="$(sha256sum "${APP_DIR}/Dockerfile" | cut -d' ' -f1)"
readonly lockfile_sha="$(sha256sum "${APP_DIR}/package-lock.json" | cut -d' ' -f1)"
readonly local_prisma_schema_sha="$(sha256sum "${APP_DIR}/prisma/schema.prisma" | cut -d' ' -f1)"
cp -R "${APP_DIR}/prisma" "${temp_dir}/prisma"
cp "${temp_dir}/prisma/schema.prisma" "${temp_dir}/schema.formatted.prisma"
if (cd "${temp_dir}" && \
  DATABASE_URL="postgresql://unused:unused@127.0.0.1:1/unused" \
  "${APP_DIR}/node_modules/.bin/prisma" format \
    --schema "${temp_dir}/schema.formatted.prisma" \
    >"${temp_dir}/prisma-format.log" 2>&1); then
  :
else
  fail "pinned Prisma could not normalize the local schema for generated-client comparison"
fi
if grep -Fq "Environment variables loaded from" "${temp_dir}/prisma-format.log"; then
  fail "pinned Prisma format unexpectedly loaded an environment file"
fi
readonly formatted_prisma_schema_sha="$(sha256sum "${temp_dir}/schema.formatted.prisma" | cut -d' ' -f1)"
readonly candidate_image_id="$(docker image inspect "${CANDIDATE_IMAGE}" --format '{{.Id}}')"
readonly candidate_revision_label="$(docker image inspect "${candidate_image_id}" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
readonly candidate_inputs_label="$(docker image inspect "${candidate_image_id}" --format "{{index .Config.Labels \"${INPUTS_LABEL}\"}}")"
readonly postgres_image_id="$(docker image inspect "${POSTGRES_IMAGE}" --format '{{.Id}}')"
readonly redis_image_id="$(docker image inspect "${REDIS_IMAGE}" --format '{{.Id}}')"
readonly generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[[ "${#source_sha}" -eq 40 ]] || fail "HEAD must resolve to a full commit SHA"
[[ "${candidate_revision_label}" == "${source_sha}" ]] || fail "candidate revision label does not match HEAD"
[[ "${candidate_inputs_label}" == "${source_inputs_sha256}" ]] || fail "candidate source-input label does not match clean HEAD inputs"

log "Phase 0 candidate image smoke"
log "generated_at=${generated_at}"
log "source_sha=${source_sha}"
log "source_inputs_sha256=${source_inputs_sha256} candidate_revision_label=matched candidate_inputs_label=matched"
log "dockerfile_sha256=${dockerfile_sha}"
log "package_lock_sha256=${lockfile_sha}"
log "local_prisma_schema_sha256=${local_prisma_schema_sha}"
log "formatted_prisma_schema_sha256=${formatted_prisma_schema_sha} runner=local-pinned-prisma"
log "candidate_reference=${CANDIDATE_IMAGE}"
log "candidate_image_id=${candidate_image_id}"
log "postgres_image_id=${postgres_image_id}"
log "redis_image_id=${redis_image_id}"
log "ownership_label=${OWNERSHIP_LABEL} run_id=${run_id}"
log "config=synthetic-development secrets=ephemeral-per-run real-env=not-read ambient-env=not-forwarded"
log "loopback_relays=host-owned postgres:${POSTGRES_PORT},http:${APP_PORT}"
log "preflight=ok resources=absent ports=free"

if network_id="$(docker network create --internal \
  --label "${OWNERSHIP_LABEL}=${run_id}" \
  "${NETWORK_NAME}" 2>"${temp_dir}/network-launch.log")"; then
  :
else
  network_exit=$?
  log "network_launch=failed exit=${network_exit}"
  fail "disposable Docker network could not be created"
fi
network_is_owned || fail "created network ownership identity did not match"
[[ "$(docker network inspect "${network_id}" --format '{{.Internal}}')" == "true" ]] \
  || fail "disposable Docker network is not internal"
log "network_id=${network_id} internal=true external-egress=disabled-by-docker"

if postgres_container_id="$(POSTGRES_PASSWORD="${postgres_password}" docker run --rm --detach \
  --name "${POSTGRES_CONTAINER}" \
  --label "${OWNERSHIP_LABEL}=${run_id}" \
  --network "${network_id}" \
  --memory 512m \
  --cpus 1 \
  --pids-limit 256 \
  --env POSTGRES_DB=auth_db \
  --env POSTGRES_USER=postgres \
  --env POSTGRES_PASSWORD \
  "${postgres_image_id}" 2>"${temp_dir}/postgres-launch.log")"; then
  :
else
  postgres_exit=$?
  log "postgres_launch=failed exit=${postgres_exit}"
  fail "disposable PostgreSQL container could not be launched"
fi
container_is_owned "${postgres_container_id}" "${postgres_container_id}" \
  || fail "created PostgreSQL container ownership identity did not match"

if redis_container_id="$(docker run --rm --detach \
  --name "${REDIS_CONTAINER}" \
  --label "${OWNERSHIP_LABEL}=${run_id}" \
  --network "${network_id}" \
  --memory 128m \
  --cpus 0.5 \
  --pids-limit 128 \
  "${redis_image_id}" redis-server --appendonly no 2>"${temp_dir}/redis-launch.log")"; then
  :
else
  redis_exit=$?
  log "redis_launch=failed exit=${redis_exit}"
  fail "disposable Redis container could not be launched"
fi
container_is_owned "${redis_container_id}" "${redis_container_id}" \
  || fail "created Redis container ownership identity did not match"

readonly running_postgres_image_id="$(docker container inspect "${postgres_container_id}" --format '{{.Image}}')"
readonly running_redis_image_id="$(docker container inspect "${redis_container_id}" --format '{{.Image}}')"
readonly postgres_network_count="$(docker container inspect "${postgres_container_id}" --format '{{len .NetworkSettings.Networks}}')"
readonly redis_network_count="$(docker container inspect "${redis_container_id}" --format '{{len .NetworkSettings.Networks}}')"
readonly postgres_limits="$(docker container inspect "${postgres_container_id}" --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.HostConfig.PidsLimit}}')"
readonly redis_limits="$(docker container inspect "${redis_container_id}" --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.HostConfig.PidsLimit}}')"
[[ "${running_postgres_image_id}" == "${postgres_image_id#sha256:}" || "${running_postgres_image_id}" == "${postgres_image_id}" ]] \
  || fail "running PostgreSQL image ID did not match resolved image"
[[ "${running_redis_image_id}" == "${redis_image_id#sha256:}" || "${running_redis_image_id}" == "${redis_image_id}" ]] \
  || fail "running Redis image ID did not match resolved image"
[[ "${postgres_network_count}" == "1" && "${redis_network_count}" == "1" ]] \
  || fail "dependency containers must attach only to the internal network"
[[ "${postgres_limits}" == "536870912 1000000000 256" ]] || fail "PostgreSQL resource limits mismatch"
[[ "${redis_limits}" == "134217728 500000000 128" ]] || fail "Redis resource limits mismatch"
log "postgres_container_id=${postgres_container_id} running_image_id=${running_postgres_image_id} network_count=1 limits=memory:536870912,nanocpus:1000000000,pids:256"
log "redis_container_id=${redis_container_id} running_image_id=${running_redis_image_id} network_count=1 limits=memory:134217728,nanocpus:500000000,pids:128"

wait_for_postgres
wait_for_redis
log "dependencies=ok postgres=16 redis=7.4"

readonly postgres_internal_ip="$(docker container inspect "${postgres_container_id}" \
  --format "{{with index .NetworkSettings.Networks \"${NETWORK_NAME}\"}}{{.IPAddress}}{{end}}")"
[[ -n "${postgres_internal_ip}" ]] || fail "could not resolve disposable PostgreSQL internal address"
if start_loopback_proxy "${POSTGRES_PORT}" "${postgres_internal_ip}" "5432" "${temp_dir}/postgres-proxy.log"; then
  postgres_proxy_pid="${last_proxy_pid}"
  log "postgres_loopback_relay=ok pid=${postgres_proxy_pid} target-container-id=${postgres_container_id}"
else
  proxy_exit=$?
  postgres_proxy_pid="${last_proxy_pid}"
  log "postgres_loopback_relay=failed exit=${proxy_exit}"
  fail "host-owned PostgreSQL loopback relay could not be started"
fi

if (cd "${temp_dir}" && \
  DATABASE_URL="postgresql://postgres:${postgres_password}@127.0.0.1:${POSTGRES_PORT}/auth_db" \
  "${APP_DIR}/node_modules/.bin/prisma" migrate deploy \
    --schema "${temp_dir}/prisma/schema.prisma" \
    >"${temp_dir}/prisma.log" 2>&1); then
  log "migrations=ok runner=local-pinned-prisma"
else
  prisma_exit=$?
  log "migrations=failed runner=local-pinned-prisma exit=${prisma_exit}"
  fail "pinned Prisma migration deploy failed"
fi
if grep -Fq "Environment variables loaded from" "${temp_dir}/prisma.log"; then
  fail "pinned Prisma migration unexpectedly loaded an environment file"
fi
log "prisma_env_autoload=absent temp-cwd-and-schema=verified"

if PHASE0_CANDIDATE_IMAGE_ID="${candidate_image_id}" \
  PHASE0_NETWORK_ID="${network_id}" \
  PHASE0_POSTGRES_CONTAINER="${POSTGRES_CONTAINER}" \
  PHASE0_REDIS_CONTAINER="${REDIS_CONTAINER}" \
  PHASE0_APP_CONTAINER="${APP_CONTAINER}" \
  PHASE0_POSTGRES_PASSWORD="${postgres_password}" \
  PHASE0_RUN_ID="${run_id}" \
  PHASE0_OWNERSHIP_LABEL="${OWNERSHIP_LABEL}" \
  PHASE0_EXPECTED_KID_FILE="${temp_dir}/expected-kid" \
  PHASE0_APP_ID_FILE="${temp_dir}/app-id" \
  PHASE0_LAUNCH_STATUS_FILE="${temp_dir}/launch-status" \
  node --input-type=module >"${temp_dir}/docker-app.log" 2>&1 <<'NODE'
import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const keyId = `phase0-smoke-${randomUUID()}`;
const publicJwk = { ...publicKey.export({ format: "jwk" }), alg: "RS256", use: "sig", kid: keyId };
writeFileSync(process.env.PHASE0_EXPECTED_KID_FILE, keyId, { mode: 0o600 });

const runtimeEnvironment = {
  NODE_ENV: "development",
  DATABASE_URL: `postgresql://postgres:${process.env.PHASE0_POSTGRES_PASSWORD}@${process.env.PHASE0_POSTGRES_CONTAINER}:5432/auth_db`,
  PORT: "4000",
  JWT_ACCESS_ALGORITHM: "RS256",
  JWT_ACCESS_PRIVATE_KEY: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  JWT_ACCESS_PUBLIC_JWK: JSON.stringify(publicJwk),
  JWT_ACCESS_KEY_ID: keyId,
  JWT_REFRESH_SECRET: randomBytes(48).toString("base64url"),
  JWT_ISSUER: "https://phase0-smoke.invalid",
  JWT_AUDIENCE: "temis",
  ACCESS_TOKEN_EXPIRES_IN: "15m",
  REFRESH_TOKEN_EXPIRES_IN_DAYS: "1",
  PASSWORD_MIN_LENGTH: "8",
  COMPANY_ALLOWED_EMAIL_DOMAIN: "",
  CORS_ALLOWED_ORIGINS: "http://127.0.0.1:3000",
  AUTH_RATE_LIMIT_WINDOW_SECONDS: "60",
  AUTH_RATE_LIMIT_MAX_REQUESTS: "20",
  AUTH_CLIENTS_JSON: JSON.stringify([{
    clientId: "temis",
    audience: "temis",
    allowedRedirectUris: [
      "https://financenow.kr/auth/callback",
      "https://temis.me/auth/callback",
      "https://ti.temis.me/auth/callback"
    ],
    allowedOrigins: ["https://financenow.kr"],
    defaultRole: { serviceKey: "temis", name: "user" }
  }]),
  REDIS_URL: `redis://${process.env.PHASE0_REDIS_CONTAINER}:6379`,
  FRONTEND_REDIRECT_URL: "http://127.0.0.1:3000/auth/callback",
  OAUTH_ENABLED_PROVIDERS: "",
  GOOGLE_CLIENT_ID: "", GOOGLE_CLIENT_SECRET: "",
  GOOGLE_REDIRECT_URI: "http://127.0.0.1:4000/auth/google/callback",
  NAVER_CLIENT_ID: "", NAVER_CLIENT_SECRET: "",
  NAVER_REDIRECT_URI: "http://127.0.0.1:4000/auth/naver/callback",
  KAKAO_CLIENT_ID: "", KAKAO_CLIENT_SECRET: "",
  KAKAO_REDIRECT_URI: "http://127.0.0.1:4000/auth/kakao/callback",
  MAIL_PROVIDER: "dev",
  MAIL_FROM: "Phase 0 Smoke <no-reply@phase0-smoke.invalid>",
  MAIL_REPLY_TO: "",
  RESEND_API_KEY: "", RESEND_ADMIN_KEY: "",
  SMTP_HOST: "", SMTP_PORT: "587", SMTP_USERNAME: "", SMTP_PASSWORD: ""
};
const args = [
  "run", "--rm", "--detach",
  "--name", process.env.PHASE0_APP_CONTAINER,
  "--label", `${process.env.PHASE0_OWNERSHIP_LABEL}=${process.env.PHASE0_RUN_ID}`,
  "--network", process.env.PHASE0_NETWORK_ID,
  "--memory", "512m",
  "--cpus", "1",
  "--pids-limit", "256",
  "--cap-drop", "ALL",
  "--security-opt", "no-new-privileges=true",
  "--read-only",
  "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m"
];
for (const key of Object.keys(runtimeEnvironment)) args.push("--env", key);
args.push(process.env.PHASE0_CANDIDATE_IMAGE_ID);

const result = spawnSync("docker", args, {
  env: { PATH: process.env.PATH, ...runtimeEnvironment },
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});
writeFileSync(process.env.PHASE0_LAUNCH_STATUS_FILE, String(result.status ?? 1), { mode: 0o600 });
if (result.status === 0) {
  writeFileSync(process.env.PHASE0_APP_ID_FILE, result.stdout.trim(), { mode: 0o600 });
}
process.exit(result.status ?? 1);
NODE
then
  app_container_id="$(<"${temp_dir}/app-id")"
else
  launch_exit="$(<"${temp_dir}/launch-status" 2>/dev/null || printf unknown)"
  log "candidate_launch=failed exit=${launch_exit}"
  fail "candidate app container could not be launched with synthetic configuration"
fi

container_is_owned "${app_container_id}" "${app_container_id}" \
  || fail "created candidate container ownership identity did not match"
readonly running_app_image_id="$(docker container inspect "${app_container_id}" --format '{{.Image}}')"
readonly app_network_count="$(docker container inspect "${app_container_id}" --format '{{len .NetworkSettings.Networks}}')"
readonly app_limits="$(docker container inspect "${app_container_id}" --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.HostConfig.PidsLimit}}')"
readonly app_readonly_rootfs="$(docker container inspect "${app_container_id}" --format '{{.HostConfig.ReadonlyRootfs}}')"
readonly app_cap_drop="$(docker container inspect "${app_container_id}" --format '{{join .HostConfig.CapDrop ","}}')"
readonly app_security_opt="$(docker container inspect "${app_container_id}" --format '{{join .HostConfig.SecurityOpt ","}}')"
readonly app_tmpfs="$(docker container inspect "${app_container_id}" --format '{{index .HostConfig.Tmpfs "/tmp"}}')"
[[ "${running_app_image_id}" == "${candidate_image_id#sha256:}" || "${running_app_image_id}" == "${candidate_image_id}" ]] \
  || fail "running candidate image ID did not match resolved immutable image"
[[ "${app_network_count}" == "1" ]] || fail "candidate app must attach only to the internal network"
[[ "${app_limits}" == "536870912 1000000000 256" ]] || fail "candidate app resource limits mismatch"
[[ "${app_readonly_rootfs}" == "true" ]] || fail "candidate app root filesystem must be read-only"
[[ "${app_cap_drop}" == "ALL" ]] || fail "candidate app must drop all Linux capabilities"
[[ "${app_security_opt}" == *"no-new-privileges=true"* || "${app_security_opt}" == *"no-new-privileges:true"* ]] \
  || fail "candidate app must set no-new-privileges"
[[ "${app_tmpfs}" == *"rw"* && "${app_tmpfs}" == *"noexec"* && "${app_tmpfs}" == *"nosuid"* \
  && "${app_tmpfs}" == *"nodev"* \
  && ( "${app_tmpfs}" == *"size=67108864"* || "${app_tmpfs}" == *"size=64m"* ) ]] \
  || fail "candidate app /tmp tmpfs security options mismatch"
log "app_container_id=${app_container_id} running_image_id=${running_app_image_id} network_count=1 limits=memory:536870912,nanocpus:1000000000,pids:256 security=cap-drop-all,no-new-privileges,read-only,tmpfs-tmp"
log "candidate_launch=ok immutable-image-id=matched config=synthetic secrets=ephemeral oauth=disabled mail=dev"

readonly image_schema_hashes="$(docker exec "${app_container_id}" node -e '
  const { createHash } = require("node:crypto");
  const { readFileSync } = require("node:fs");
  const hash = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
  process.stdout.write(`${hash("/app/prisma/schema.prisma")} ${hash("/app/node_modules/.prisma/client/schema.prisma")}`);
')"
read -r image_prisma_schema_sha generated_client_schema_sha <<<"${image_schema_hashes}"
[[ "${image_prisma_schema_sha}" == "${local_prisma_schema_sha}" ]] \
  || fail "image Prisma schema hash does not match local clean input"
[[ "${generated_client_schema_sha}" == "${formatted_prisma_schema_sha}" ]] \
  || fail "generated Prisma client schema hash does not match pinned-Prisma-normalized local schema"
log "image_prisma_schema_sha256=${image_prisma_schema_sha} generated_client_schema_sha256=${generated_client_schema_sha} raw-and-normalized-local-schema=matched"

if docker exec "${app_container_id}" node -e '
  const socket = require("node:net").createConnection({ host: "1.1.1.1", port: 443 });
  socket.setTimeout(2000);
  socket.once("connect", () => process.exit(1));
  socket.once("error", () => process.exit(0));
  socket.once("timeout", () => process.exit(0));
' >/dev/null 2>&1; then
  log "app_external_egress=blocked active-probe=PASS"
else
  fail "candidate app unexpectedly reached an external probe address"
fi

readonly app_internal_ip="$(docker container inspect "${app_container_id}" \
  --format "{{with index .NetworkSettings.Networks \"${NETWORK_NAME}\"}}{{.IPAddress}}{{end}}")"
[[ -n "${app_internal_ip}" ]] || fail "could not resolve candidate app internal address"
if start_loopback_proxy "${APP_PORT}" "${app_internal_ip}" "4000" "${temp_dir}/app-proxy.log"; then
  app_proxy_pid="${last_proxy_pid}"
  log "app_loopback_relay=ok pid=${app_proxy_pid} target-container-id=${app_container_id}"
else
  proxy_exit=$?
  app_proxy_pid="${last_proxy_pid}"
  log "app_loopback_relay=failed exit=${proxy_exit}"
  fail "host-owned app loopback relay could not be started"
fi

wait_for_endpoint "/healthz"
log "healthz=ok status=200"
wait_for_endpoint "/readyz"
log "readyz=ok status=200 database=reachable"

if curl --fail --silent --show-error --max-time 5 \
  "http://127.0.0.1:${APP_PORT}/.well-known/jwks.json" \
  --output "${temp_dir}/jwks.json" 2>"${temp_dir}/jwks-curl.log"; then
  :
else
  jwks_curl_exit=$?
  log "jwks_fetch=failed exit=${jwks_curl_exit}"
  fail "JWKS endpoint could not be fetched"
fi

if PHASE0_EXPECTED_KID_FILE="${temp_dir}/expected-kid" \
  PHASE0_JWKS_FILE="${temp_dir}/jwks.json" \
  node --input-type=module >/dev/null 2>&1 <<'NODE'
import { readFile } from "node:fs/promises";
const expectedKid = await readFile(process.env.PHASE0_EXPECTED_KID_FILE, "utf8");
const jwks = JSON.parse(await readFile(process.env.PHASE0_JWKS_FILE, "utf8"));
const key = Array.isArray(jwks.keys) ? jwks.keys.find((candidate) => candidate?.kid === expectedKid) : undefined;
if (!key || key.kty !== "RSA" || key.alg !== "RS256" || key.use !== "sig"
    || typeof key.n !== "string" || key.n.length === 0
    || typeof key.e !== "string" || key.e.length === 0) process.exit(1);
NODE
then
  log "jwks=ok kty=RSA alg=RS256 use=sig ephemeral-kid=matched"
else
  fail "JWKS did not contain the ephemeral configured RS256 signing key"
fi
log "evidence_redaction=ok synthetic-secret-values=never-emitted"
