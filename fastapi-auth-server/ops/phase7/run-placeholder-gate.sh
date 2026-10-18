#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
  echo "usage: run-placeholder-gate.sh GATE EVIDENCE_DIR" >&2
  exit 2
fi

readonly GATE="$1"
readonly EVIDENCE_DIR="$2"

case "${GATE}" in
  performance|security|chaos|backup-restore|local-rollback) ;;
  *)
    echo "unknown Phase 7 placeholder gate: ${GATE}" >&2
    exit 2
    ;;
esac

printf 'gate=%s\nstatus=SKIP\nreason=not-implemented\n' "${GATE}" \
  >"${EVIDENCE_DIR}/${GATE}.status"
echo "Phase 7 ${GATE} gate is not implemented; qualification remains incomplete" >&2
exit 3
