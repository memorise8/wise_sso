#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly FASTAPI_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly ENV_FILE="${FASTAPI_DIR}/.env.example"
readonly PROBE_FILE="${FASTAPI_DIR}/tests/helpers/gitlab_oidc_probe.rb"
readonly PYTHON="${FASTAPI_DIR}/.venv/bin/python"
readonly GITLAB_IMAGE_ID="sha256:9bbf2223cbbae4c78854a65094e7ee00a9464796b48257d3d0b716a2154278c4"

if env | grep -Eq '^(DOCKER_HOST|DOCKER_CONTEXT|DATABASE_URL|REDIS_URL)='; then
  echo "Clear ambient Docker/SSO endpoint overrides before the GitLab OIDC probe" >&2
  exit 2
fi

command -v docker >/dev/null
test -x "${PYTHON}"
test -r "${ENV_FILE}"
test -r "${PROBE_FILE}"

readonly DOCKER_ENDPOINT="$(docker context inspect --format '{{.Endpoints.docker.Host}}' "$(docker context show)")"
if [[ "${DOCKER_ENDPOINT}" != unix://* ]]; then
  echo "GitLab OIDC probe requires a local Unix-socket Docker engine" >&2
  exit 3
fi

readonly RESOLVED_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${GITLAB_IMAGE_ID}")"
if [[ "${RESOLVED_IMAGE_ID}" != "${GITLAB_IMAGE_ID}" ]]; then
  echo "Pinned GitLab image identity mismatch" >&2
  exit 4
fi

readonly PROBE_TMP_DIR="$(mktemp -d)"
readonly CID_FILE="${PROBE_TMP_DIR}/container.cid"

cleanup() {
  local original_status=$?
  local container_id=""
  trap - EXIT INT TERM
  set +e
  if [[ -s "${CID_FILE}" ]]; then
    IFS= read -r container_id <"${CID_FILE}"
    if [[ "${container_id}" =~ ^[0-9a-f]{64}$ ]]; then
      docker rm --force "${container_id}" >/dev/null 2>&1 || true
    fi
  fi
  rm -f -- "${CID_FILE}"
  rmdir -- "${PROBE_TMP_DIR}" 2>/dev/null || true
  exit "${original_status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

generate_fixture() {
  cd "${FASTAPI_DIR}"
  PYTHONPATH="${FASTAPI_DIR}/src" "${PYTHON}" - "${ENV_FILE}" <<'PYTHON'
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from dotenv import dotenv_values

from wiseacct_sso.config import Settings
from wiseacct_sso.infrastructure.oidc_tokens import (
    OidcIdTokenIdentity,
    OidcIdTokenSigner,
)

env_file = Path(sys.argv[1])
settings = Settings(
    **{key: value for key, value in dotenv_values(env_file).items() if value is not None}
)
signer = OidcIdTokenSigner.from_settings(settings)
client_id = "gitlab-temis-probe"
nonce = "gitlab-synthetic-probe-nonce"
now = datetime.now(UTC).replace(microsecond=0)
identity = OidcIdTokenIdentity(
    user_id="synthetic-gitlab-user",
    email="synthetic-gitlab-user@example.invalid",
    email_verified=True,
    name="Synthetic GitLab User",
    groups=("gitlab:user",),
)
valid = signer.issue(identity, client_id=client_id, nonce=nonce)

base_claims = {
    "sub": identity.user_id,
    "email": identity.email,
    "email_verified": identity.email_verified,
    "name": identity.name,
    "groups": list(identity.groups),
    "iat": int(now.timestamp()),
    "exp": int((now + timedelta(minutes=5)).timestamp()),
    "iss": settings.jwt_issuer,
    "aud": client_id,
    "nonce": nonce,
}


def signed(**overrides: object) -> str:
    claims = base_claims | overrides
    return jwt.encode(
        claims,
        settings.jwt_access_private_key,
        algorithm="RS256",
        headers={"kid": settings.jwt_access_key_id},
    )


header, payload, signature = valid.split(".")
replacement = "A" if signature[0] != "A" else "B"
bad_signature = ".".join((header, payload, replacement + signature[1:]))
fixture = {
    "issuer": settings.jwt_issuer,
    "client_id": client_id,
    "client_secret": "synthetic-gitlab-probe-secret",
    "redirect_uri": "https://gitlab.example.invalid/users/auth/openid_connect/callback",
    "nonce": nonce,
    "access_token": "synthetic-gitlab-userinfo-bearer",
    "jwks": {"keys": [settings.jwt_access_public_jwk.model_dump()]},
    "userinfo": {
        "sub": identity.user_id,
        "email": identity.email,
        "email_verified": identity.email_verified,
        "name": identity.name,
        "groups": list(identity.groups),
    },
    "id_tokens": {
        "valid": valid,
        "bad_signature": bad_signature,
        "wrong_audience": signed(aud="wrong-client"),
        "wrong_issuer": signed(iss="https://wrong-issuer.example.invalid"),
        "wrong_nonce": signed(nonce="wrong-nonce"),
        "expired": signed(
            iat=int((now - timedelta(minutes=10)).timestamp()),
            exp=int((now - timedelta(minutes=5)).timestamp()),
        ),
    },
}
print(json.dumps(fixture, separators=(",", ":")))
PYTHON
}

readonly RUBY_PROBE="$(<"${PROBE_FILE}")"
generate_fixture | docker run --rm --interactive --pull=never \
  --cidfile "${CID_FILE}" \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --memory 256m \
  --cpus 1 \
  --tmpfs /etc/gitlab:rw,noexec,nosuid,nodev,size=1m \
  --tmpfs /var/log/gitlab:rw,noexec,nosuid,nodev,size=1m \
  --tmpfs /var/opt/gitlab:rw,noexec,nosuid,nodev,size=1m \
  --entrypoint /opt/gitlab/embedded/bin/ruby \
  "${GITLAB_IMAGE_ID}" -e "${RUBY_PROBE}"
