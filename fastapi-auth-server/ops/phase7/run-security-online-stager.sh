#!/bin/sh
set -eu
umask 077

phase7_dir=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)
repo=$(CDPATH= cd -- "$phase7_dir/../../.." && pwd -P)

if [ "$#" -ne 4 ]; then
  echo "usage: $0 check|collect RUN_ID linux/amd64|linux/arm64/v8 ABSOLUTE_PRIVATE_OUTPUT_PARENT" >&2
  exit 2
fi

case "$4" in
  /*) ;;
  *) echo "security stager output parent must be absolute" >&2; exit 2 ;;
esac

exec /usr/bin/env -i \
  PATH=/usr/bin:/bin \
  /usr/bin/python3 -I "$phase7_dir/security/online_stager.py" \
  "$1" "$2" "$3" "$4" --repo "$repo"
