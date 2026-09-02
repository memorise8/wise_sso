#!/bin/sh
set -eu
umask 077

phase7_dir=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)
repo=$(CDPATH= cd -- "$phase7_dir/../../.." && pwd -P)

if [ "$#" -ne 2 ]; then
  echo "usage: $0 ABSOLUTE_PRIVATE_STAGER_INPUT_DIR RUN_ID" >&2
  exit 2
fi

case "$1" in
  /*) ;;
  *) echo "security stager input directory must be absolute" >&2; exit 2 ;;
esac

exec /usr/bin/env -i \
  PATH=/usr/bin:/bin \
  /usr/bin/python3 -I "$phase7_dir/security/offline_stager_intake.py" \
  --input "$1" \
  --run-id "$2" \
  --repo "$repo" \
  --evidence-root "$repo/fastapi-auth-server/evidence/phase7-security-stager-intake"
