#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: check-placeholder-result.sh GATE EVIDENCE_DIR EXIT_CODE" >&2
  exit 2
fi

readonly GATE="$1"
readonly EVIDENCE_DIR="$2"
readonly EXIT_CODE="$3"
readonly STATUS_FILE="${EVIDENCE_DIR}/${GATE}.status"
readonly EXPECTED="$(printf 'gate=%s\nstatus=SKIP\nreason=not-implemented' "${GATE}")"

if [[ "${EXIT_CODE}" == "3" && -f "${STATUS_FILE}" ]] \
  && [[ "$(cat -- "${STATUS_FILE}")" == "${EXPECTED}" ]]; then
  exit 0
fi

echo "Phase 7 ${GATE} placeholder returned an unexpected result (${EXIT_CODE})" >&2
if [[ "${EXIT_CODE}" =~ ^[1-9][0-9]*$ ]] && (( EXIT_CODE <= 255 )); then
  exit "${EXIT_CODE}"
fi
exit 1
