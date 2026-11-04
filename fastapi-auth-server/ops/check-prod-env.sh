#!/usr/bin/env bash
# Export production environment privately before running; never source untrusted env files.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m wiseacct_sso.ops.check_prod_env "$@"
