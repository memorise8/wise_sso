#!/usr/bin/env bash
# Run from the wise_sso repository root. Always include the lab overlay.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in
  build)
    docker build -t wise-sso-integration-lab:local integration-lab
    ;;
  setup)
    docker run --rm --user "$(id -u):$(id -g)" \
      --mount "type=bind,source=$PWD/integration-lab,target=/lab" \
      wise-sso-integration-lab:local python setup.py
    ;;
  config|up|ps|logs|stop|seed|policy-setup|policy-check|sso-check|bulk-check|admin-login-check)
    test -f integration-lab/.local/compose.env || { echo 'Run build and setup first'; exit 1; }
    compose=(docker compose --env-file integration-lab/.local/compose.env \
      -f docker-compose.oauth-local.yml -f integration-lab/compose.yml)
    case "$1" in
      config) "${compose[@]}" config --quiet ;;
      up)
        "${compose[@]}" up -d --wait --wait-timeout 120 app dummy-customer dummy-staff lab-tls
        "${compose[@]}" exec -T lab-tls nginx -s reload
        ;;
      ps) "${compose[@]}" ps ;;
      logs) "${compose[@]}" logs --tail=80 app dummy-customer dummy-staff lab-tls ;;
      seed) "${compose[@]}" exec -T app python - < integration-lab/seed.py ;;
      policy-setup) "${compose[@]}" exec -T app python - setup < integration-lab/policy.py ;;
      policy-check) "${compose[@]}" exec -T app python - check < integration-lab/policy.py ;;
      sso-check) "${compose[@]}" exec -T app python - < integration-lab/sso-check.py ;;
      bulk-check) "${compose[@]}" exec -T app python - < integration-lab/bulk-check.py ;;
      admin-login-check) "${compose[@]}" exec -T app python - < integration-lab/admin-login-check.py ;;
      stop) "${compose[@]}" stop lab-tls dummy-customer dummy-staff ;;
    esac
    ;;
  *) echo 'Usage: bash integration-lab/lab.sh build|setup|config|up|ps|seed|policy-setup|policy-check|sso-check|bulk-check|admin-login-check|logs|stop'; exit 1 ;;
esac
