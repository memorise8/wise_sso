#!/usr/bin/env bash
set -euo pipefail

readonly APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_DIR="$(cd "${APP_DIR}/.." && pwd)"
readonly INPUTS_LABEL="com.wiseacct.sso.source-inputs-sha256"
readonly CANDIDATE_TAG="${1:-}"
readonly -a BUILD_INPUTS=(
  auth-server/Dockerfile
  auth-server/package.json
  auth-server/package-lock.json
  auth-server/tsconfig.json
  auth-server/prisma
  auth-server/src
  auth-server/public
)

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

[[ $# -eq 1 && -n "${CANDIDATE_TAG}" && "${CANDIDATE_TAG}" != -* ]] \
  || fail "usage: $0 <explicit-candidate-tag>"
command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v git >/dev/null 2>&1 || fail "git is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"

readonly source_revision="$(git -C "${REPO_DIR}" rev-parse --verify HEAD^{commit})"
[[ "${#source_revision}" -eq 40 ]] || fail "HEAD must resolve to a full commit SHA"

readonly input_status="$(git -C "${REPO_DIR}" status --porcelain=v1 --untracked-files=all -- "${BUILD_INPUTS[@]}")"
[[ -z "${input_status}" ]] \
  || fail "candidate build inputs must have no tracked or untracked changes relative to HEAD"

readonly tree_listing="$(git -C "${REPO_DIR}" ls-tree -r HEAD -- "${BUILD_INPUTS[@]}")"
[[ -n "${tree_listing}" ]] || fail "candidate build inputs are missing from HEAD"
readonly source_inputs_hash_line="$(printf '%s\n' "${tree_listing}" | sha256sum)"
readonly source_inputs_sha256="${source_inputs_hash_line%% *}"

printf 'phase0-image-build source_revision=%s source_inputs_sha256=%s candidate_tag=%s\n' \
  "${source_revision}" "${source_inputs_sha256}" "${CANDIDATE_TAG}"

docker build \
  --pull=false \
  --file "${APP_DIR}/Dockerfile" \
  --tag "${CANDIDATE_TAG}" \
  --build-arg "SOURCE_REVISION=${source_revision}" \
  --build-arg "SOURCE_INPUTS_SHA256=${source_inputs_sha256}" \
  --label "org.opencontainers.image.revision=${source_revision}" \
  --label "${INPUTS_LABEL}=${source_inputs_sha256}" \
  "${APP_DIR}"

readonly image_id="$(docker image inspect "${CANDIDATE_TAG}" --format '{{.Id}}')"
readonly image_revision="$(docker image inspect "${image_id}" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
readonly image_inputs_sha="$(docker image inspect "${image_id}" --format "{{index .Config.Labels \"${INPUTS_LABEL}\"}}")"
[[ "${image_revision}" == "${source_revision}" ]] || fail "built image revision label mismatch"
[[ "${image_inputs_sha}" == "${source_inputs_sha256}" ]] || fail "built image inputs label mismatch"

printf 'phase0-image-build result=PASS image_id=%s\n' "${image_id}"
