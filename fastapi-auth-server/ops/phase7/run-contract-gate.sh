#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo "run-contract-gate.sh was replaced by the independent stateful gate" >&2
exec "${SCRIPT_DIR}/run-independent-contract-gate.sh" "$@"
