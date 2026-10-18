#!/bin/dash

TRUSTED_PATH_BOOTSTRAP="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
if [ "${WISEACCT_PHASE7_SANITIZED_ENV:-}" != "1" ]; then
  [ "${PATH:-}" = "${TRUSTED_PATH_BOOTSTRAP}" ] || {
    printf 'ERROR: ambient PATH tool substitution is forbidden\n' >&2
    exit 1
  }
  ambient_exports="$(export -p)"
  case "${ambient_exports}" in
    *"export GIT_"*)
      printf 'ERROR: ambient Git routing/configuration variables are forbidden\n' >&2
      exit 1
      ;;
    *"export DOCKER_"*)
      printf 'ERROR: ambient Docker routing/configuration variables are forbidden\n' >&2
      exit 1
      ;;
  esac
  for variable in TAR_OPTIONS GZIP BZIP BZIP2 XZ_OPT GREP_OPTIONS GREP_COLORS \
    AWKPATH AWKLIBPATH POSIXLY_CORRECT BLOCK_SIZE TMPDIR CDPATH ENV BASH_ENV; do
    eval "variable_is_set=\${${variable}+yes}"
    if [ "${variable_is_set:-}" = "yes" ]; then
      printf 'ERROR: ambient external-tool option variable is forbidden: %s\n' "${variable}" >&2
      exit 1
    fi
  done
  exec /usr/bin/env -i PATH="${TRUSTED_PATH_BOOTSTRAP}" LC_ALL=C \
    WISEACCT_PHASE7_SANITIZED_ENV=1 /usr/bin/bash "$0" "$@"
fi

set -euo pipefail
readonly TRUSTED_PATH="${TRUSTED_PATH_BOOTSTRAP}"

readonly APP_REL="fastapi-auth-server"
readonly APP_DIR="$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/../..")"
readonly REPO_DIR="$(/usr/bin/realpath -e -- "${APP_DIR}/..")"
readonly MODE="${1:-}"
readonly EXPECTED_REVISION="${2:-}"
readonly -a SOURCE_PATHS=(
  "${APP_REL}/Dockerfile" "${APP_REL}/pyproject.toml" "${APP_REL}/uv.lock"
  "${APP_REL}/README.md" "${APP_REL}/src"
)

fail() { /usr/bin/printf 'ERROR: %s\n' "$1" >&2; exit 1; }
regular_nonlink() { [[ -f "$1" && ! -L "$1" ]]; }
hash_file() { /usr/bin/sha256sum -- "$1" | /usr/bin/cut -d' ' -f1; }
git_clean() {
  /usr/bin/env -i PATH="${TRUSTED_PATH}" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_NO_LAZY_FETCH=1 /usr/bin/git --no-replace-objects \
    -c core.fsmonitor=false -c core.untrackedCache=false -c core.quotePath=true \
    -C "${REPO_DIR}" "$@"
}
cleanup() {
  if [[ -n "${private_dir:-}" && -d "${private_dir}" ]]; then
    /usr/bin/chmod -R u+rwX "${private_dir}" 2>/dev/null || true
    /usr/bin/rm -rf -- "${private_dir}"
  fi
}

[[ "${MODE}" == "--check-only" || "${MODE}" == "--build" ]] \
  || fail "usage: $0 (--check-only|--build) <expected-40-character-HEAD>"
[[ $# -eq 2 && "${EXPECTED_REVISION}" =~ ^[0-9a-f]{40}$ ]] \
  || fail "expected HEAD must be an explicit lowercase 40-character commit SHA"
for tool in /usr/bin/awk /usr/bin/basename /usr/bin/chmod /usr/bin/cut /usr/bin/dirname \
  /usr/bin/env /usr/bin/find /usr/bin/git /usr/bin/grep /usr/bin/mkdir /usr/bin/mktemp \
  /usr/bin/printf /usr/bin/realpath /usr/bin/rm /usr/bin/sha256sum /usr/bin/sort \
  /usr/bin/stat /usr/bin/tar /usr/bin/wc; do
  [[ -x "${tool}" ]] || fail "required pinned tool is unavailable: ${tool}"
done

readonly repo_top="$(git_clean rev-parse --show-toplevel)"
[[ "$(/usr/bin/realpath -e -- "${repo_top}")" == "${REPO_DIR}" ]] \
  || fail "script must run from its containing repository"
[[ "$(git_clean rev-parse --is-bare-repository)" == false ]] || fail "bare repositories are forbidden"
readonly git_dir="$(git_clean rev-parse --absolute-git-dir)"
readonly common_dir_value="$(git_clean rev-parse --git-common-dir)"
if [[ "${common_dir_value}" == /* ]]; then
  readonly git_common_dir="$(/usr/bin/realpath -e -- "${common_dir_value}")"
else
  readonly git_common_dir="$(/usr/bin/realpath -e -- "${REPO_DIR}/${common_dir_value}")"
fi
[[ -d "${git_dir}" && ! -L "${git_dir}" && -d "${git_common_dir}" && ! -L "${git_common_dir}" ]] \
  || fail "Git metadata directories must be real non-symlink directories"
[[ ! -e "${git_common_dir}/objects/info/alternates" && ! -e "${git_common_dir}/objects/info/http-alternates" ]] \
  || fail "Git object alternates are forbidden"
[[ -z "$(git_clean for-each-ref --format='%(refname)' refs/replace/)" ]] \
  || fail "Git replacement refs are forbidden"
unsafe_object_config() {
  /usr/bin/awk '{
    key=tolower($1)
    if (key == "extensions.partialclone" || key ~ /promisor/ || key ~ /alternate/) print
  }'
}
include_directives() {
  /usr/bin/awk '{
    key=tolower($1)
    if (key == "include.path" || key ~ /^includeif\..*\.path$/) print
  }'
}
readonly local_git_config="$(git_clean config --no-includes --local --get-regexp '.*' 2>/dev/null || true)"
[[ -z "$(/usr/bin/printf '%s\n' "${local_git_config}" | include_directives)" ]] \
  || fail "Git config include directives are forbidden in common Git config"
[[ -z "$(/usr/bin/printf '%s\n' "${local_git_config}" | unsafe_object_config)" ]] \
  || fail "partial-clone/promisor/alternate object material is forbidden in common Git config"
readonly worktree_config_enabled="$(
  git_clean config --no-includes --local --type=bool --get extensions.worktreeConfig 2>/dev/null || true
)"
if [[ "${worktree_config_enabled}" == "true" ]]; then
  readonly worktree_git_config="$(git_clean config --no-includes --worktree --get-regexp '.*' 2>/dev/null || true)"
  [[ -z "$(/usr/bin/printf '%s\n' "${worktree_git_config}" | include_directives)" ]] \
    || fail "Git config include directives are forbidden in worktree Git config"
  [[ -z "$(/usr/bin/printf '%s\n' "${worktree_git_config}" | unsafe_object_config)" ]] \
    || fail "partial-clone/promisor/alternate object material is forbidden in worktree Git config"
fi

readonly worktree_dotgit="${REPO_DIR}/.git"
readonly git_dir_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${git_dir}")"
readonly git_common_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${git_common_dir}")"
if [[ "${git_dir}" == "${git_common_dir}" ]]; then
  [[ -d "${worktree_dotgit}" && ! -L "${worktree_dotgit}" ]] \
    || fail "standalone repository .git must be a real directory"
  readonly git_binding_kind="standalone"
  readonly git_binding_sha256="$(/usr/bin/printf 'standalone\n' | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)"
else
  regular_nonlink "${worktree_dotgit}" || fail "linked worktree .git must be a regular non-symlink gitfile"
  regular_nonlink "${git_dir}/commondir" || fail "linked worktree commondir descriptor is invalid"
  regular_nonlink "${git_dir}/gitdir" || fail "linked worktree backlink descriptor is invalid"
  mapfile -t dotgit_lines <"${worktree_dotgit}"
  [[ "${#dotgit_lines[@]}" -eq 1 && "${dotgit_lines[0]}" == "gitdir: ${git_dir}" ]] \
    || fail "linked worktree gitfile target is not its exact canonical Git directory"
  [[ "$(/usr/bin/dirname -- "${git_dir}")" == "${git_common_dir}/worktrees" ]] \
    || fail "linked worktree Git directory is outside the common worktrees namespace"
  [[ "$(/usr/bin/basename -- "${git_dir}")" =~ ^[A-Za-z0-9._-]+$ ]] \
    || fail "linked worktree metadata slot has an unsafe name"
  [[ "$(<"${git_dir}/commondir")" == "../.." && "$(<"${git_dir}/gitdir")" == "${worktree_dotgit}" ]] \
    || fail "linked worktree backlink does not identify this exact worktree"
  readonly git_binding_kind="linked"
  readonly git_binding_sha256="$({ /usr/bin/sha256sum "${worktree_dotgit}" "${git_dir}/commondir" "${git_dir}/gitdir"; } \
    | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)"
fi
regular_nonlink "${git_dir}/HEAD" || fail "worktree HEAD descriptor is invalid"
regular_nonlink "${git_dir}/index" || fail "worktree index is absent or unsafe"
readonly resolved_index="$(/usr/bin/realpath -e -- "$(git_clean rev-parse --git-path index)")"
[[ "${resolved_index}" == "${git_dir}/index" ]] || fail "Git index does not belong to this exact worktree"

readonly source_revision="$(git_clean rev-parse --verify HEAD^{commit})"
[[ "${source_revision}" == "${EXPECTED_REVISION}" ]] || fail "HEAD does not equal the explicitly expected revision"
[[ -z "$(git_clean status --porcelain=v1 --untracked-files=all)" ]] \
  || fail "the entire repository must be clean at the exact expected HEAD"
[[ "$(git_clean write-tree)" == "$(git_clean rev-parse --verify HEAD^{tree})" ]] \
  || fail "the exact worktree index does not match the expected HEAD tree"
readonly tracked_listing="$(git_clean ls-tree -r "${source_revision}" -- "${SOURCE_PATHS[@]}")"
[[ -n "${tracked_listing}" ]] || fail "source inputs are absent from the expected commit"
[[ -z "$(/usr/bin/printf '%s\n' "${tracked_listing}" | /usr/bin/awk '$2 != "blob" || $1 !~ /^100(644|755)$/')" ]] \
  || fail "source inputs must contain only regular tracked blobs"
[[ -z "$(/usr/bin/printf '%s\n' "${tracked_listing}" | /usr/bin/awk -F '\t' '$2 !~ /^fastapi-auth-server\/[A-Za-z0-9_.\/-]+$/')" ]] \
  || fail "source input paths contain unsupported characters"
for required in "${SOURCE_PATHS[@]:0:4}"; do
  /usr/bin/grep -Fq $'\t'"${required}" <<<"${tracked_listing}" \
    || fail "required source input is absent from the expected commit: ${required}"
done
/usr/bin/grep -Fq $'\t'"${APP_REL}/src/" <<<"${tracked_listing}" || fail "tracked src input set is empty"
readonly source_inputs_sha256="$(/usr/bin/printf '%s\n' "${tracked_listing}" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)"

worktree_manifest() {
  while IFS=$'\t' read -r metadata tracked_path; do
    read -r _mode _type blob_id <<<"${metadata}"
    local source_path="${REPO_DIR}/${tracked_path}"
    regular_nonlink "${source_path}" || fail "tracked worktree source is absent or unsafe"
    [[ "$(git_clean hash-object --no-filters -- "${source_path}")" == "${blob_id}" ]] \
      || fail "tracked worktree source differs from the pinned HEAD blob"
    /usr/bin/printf '%s\t%s\t%s\n' "${tracked_path}" "$(hash_file "${source_path}")" \
      "$(/usr/bin/stat -Lc '%d:%i:%s:%y:%z' -- "${source_path}")"
  done <<<"${tracked_listing}"
}
readonly initial_worktree_manifest="$(worktree_manifest)"

attest_source() {
  local phase="$1"
  [[ "$(/usr/bin/stat -Lc '%d:%i' -- "${git_dir}")" == "${git_dir_identity}" ]] \
    || fail "worktree Git directory changed ${phase}"
  [[ "$(/usr/bin/stat -Lc '%d:%i' -- "${git_common_dir}")" == "${git_common_identity}" ]] \
    || fail "Git common directory changed ${phase}"
  if [[ "${git_binding_kind}" == linked ]]; then
    local binding
    binding="$({ /usr/bin/sha256sum "${worktree_dotgit}" "${git_dir}/commondir" "${git_dir}/gitdir"; } \
      | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)"
    [[ "${binding}" == "${git_binding_sha256}" ]] || fail "linked worktree descriptors changed ${phase}"
  fi
  [[ "$(git_clean rev-parse --verify HEAD^{commit})" == "${source_revision}" ]] || fail "worktree HEAD changed ${phase}"
  [[ -z "$(git_clean status --porcelain=v1 --untracked-files=all)" ]] || fail "worktree status changed ${phase}"
  [[ "$(git_clean write-tree)" == "$(git_clean rev-parse --verify HEAD^{tree})" ]] || fail "worktree index changed ${phase}"
  [[ "$(git_clean ls-tree -r "${source_revision}" -- "${SOURCE_PATHS[@]}")" == "${tracked_listing}" ]] \
    || fail "tracked source listing changed ${phase}"
  [[ "$(worktree_manifest)" == "${initial_worktree_manifest}" ]] \
    || fail "tracked source bytes or identity changed ${phase}"
}

umask 077
private_dir="$(/usr/bin/mktemp -d /tmp/wiseacct-phase7-image.XXXXXXXX)"
trap cleanup EXIT HUP INT TERM
/usr/bin/chmod 0700 "${private_dir}"
readonly context_dir="${private_dir}/context"
/usr/bin/mkdir -m 0700 "${context_dir}"
git_clean archive --format=tar "${source_revision}" -- "${SOURCE_PATHS[@]}" \
  | /usr/bin/tar -x -C "${context_dir}" --strip-components=1
snapshot_count=0
while IFS=$'\t' read -r metadata tracked_path; do
  read -r _mode _type blob_id <<<"${metadata}"
  snapshot_path="${context_dir}/${tracked_path#"${APP_REL}/"}"
  regular_nonlink "${snapshot_path}" || fail "private tracked build context is incomplete"
  [[ "$(git_clean hash-object --no-filters -- "${snapshot_path}")" == "${blob_id}" ]] \
    || fail "private build-context blob differs from the pinned HEAD blob"
  snapshot_count=$((snapshot_count + 1))
done <<<"${tracked_listing}"
[[ "$(/usr/bin/find "${context_dir}" -type f -print | /usr/bin/wc -l)" -eq "${snapshot_count}" ]] \
  || fail "private build context contains an unexpected or missing file"
attest_source "after private context creation"

readonly dockerfile="${context_dir}/Dockerfile"
readonly external_copy_sources="$(/usr/bin/awk 'toupper($1)=="COPY" && $2 !~ /^--from=/ { for(i=2;i<NF;i++) print $i }' \
  "${dockerfile}" | /usr/bin/sort -u)"
[[ "${external_copy_sources}" == $'README.md\npyproject.toml\nsrc\nuv.lock' ]] \
  || fail "Dockerfile external COPY inputs differ from the guarded source-input set"
mapfile -t external_froms < <(/usr/bin/awk 'toupper($1)=="FROM" { for(i=2;i<=NF;i++) if($i !~ /^--/ && $i !~ /^[A-Za-z_][A-Za-z0-9_]*$/) {print $i; break} }' \
  "${dockerfile}" | /usr/bin/sort -u)
[[ "${#external_froms[@]}" -gt 0 ]] || fail "Dockerfile has no external base image"
for item in "${external_froms[@]}"; do
  [[ "${item}" =~ @sha256:[0-9a-f]{64}$ ]] || fail "every external Dockerfile base must be pinned by sha256 digest"
done
[[ "${#external_froms[@]}" -eq 1 ]] || fail "all external Dockerfile stages must use one exact base reference"
readonly base_ref="${external_froms[0]}"
[[ "${base_ref}" =~ @sha256:([0-9a-f]{64})$ ]] || fail "base digest parsing failed"
readonly base_digest="sha256:${BASH_REMATCH[1]}"

if [[ "${MODE}" == --check-only ]]; then
  attest_source "before check-only success"
  /usr/bin/printf 'phase7-image-check result=PASS docker_trust=NOT_CHECKED source_revision=%s source_inputs_sha256=%s base_digest=%s\n' \
    "${source_revision}" "${source_inputs_sha256}" "${base_digest}"
  exit 0
fi
attest_source "before controlled-toolchain refusal"
fail "INCOMPLETE: CONTROLLED_TOOLCHAIN_REQUIRED; no reviewed toolchain lock and isolated daemon collector are checked in"
