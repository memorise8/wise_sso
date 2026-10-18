# Local OIDC preview (2026-10-15)

The existing development FastAPI on loopback 4001 now enables OIDC. Express and
the existing development PostgreSQL/Redis containers were not restarted or modified.
No accounts or roles were created or granted. Production routing is unchanged.

Open **https://localhost:4443/** on the server, or forward that port from your computer:

```sh
ssh -N -L 4443:127.0.0.1:4443 ruci@192.168.0.4
```

Then open the same localhost URL on your computer. The preview uses a self-signed
localhost certificate valid for seven days; accept it only for this local test.
No public listener, DNS or Tunnel was added.

The root URL starts a password OIDC flow for `oidc-local-preview`, with a registered
callback at `https://localhost:4443/callback`. Login requires an ACTIVE, verified
development account with `gitlab:user`; an ordinary production account is not copied
into this isolated database. The callback is a landing page, **not** a complete relying
party: it does not exchange the code or create a GitLab session.

The second registered client is `gitlab-temis`, with its exact documented GitLab
callback. This only registers the SSO-side policy; no GitLab settings were applied.
Both preview clients use the public synthetic secret
`synthetic-oidc-local-test-only`. Never deploy this policy outside the local preview.
The root launcher uses a fixed synthetic state/nonce and PKCE verifier
`synthetic-local-oidc-pkce-verifier-for-browser-0001`; it is not a production RP.
Token/JWKS issuer remains the existing synthetic development issuer.

Google/Naver/Kakao OIDC callbacks are not enabled: real test-provider credentials and
approved callback registrations are still needed. No placeholder external provider
is represented as a functioning login. Cloudflare configuration is also unchanged.

## Current runtime and reproduction

From `fastapi-auth-server`, the base Compose file is `docker-compose.dev.yml` and the
OIDC-only overlay is `ops/oidc-preview.compose.yml`. It mounts
`ops/oidc-preview.nginx.conf` into a new network-local nginx proxy. Access logs are off
to avoid recording callback codes. The app retains all existing non-OIDC environment
values. Certificate material is local, untracked, under
`/tmp/wiseacct-oidc-preview-tls.MTxQIzol`; it must be regenerated if removed or expired.

```sh
env -i PATH="$PATH" \
  WISEACCT_FASTAPI_DEV_ENV_FILE=/home/ruci/repo/wiseacct_sso_fastapi_provisional/fastapi-auth-server/.env.example \
  WISEACCT_OIDC_PREVIEW_TLS_DIR=/tmp/wiseacct-oidc-preview-tls.MTxQIzol \
  docker compose --project-name wiseacct-sso-fastapi-dev \
  --env-file /home/ruci/repo/wiseacct_sso_fastapi_provisional/fastapi-auth-server/.env.example \
  -f docker-compose.dev.yml -f ops/oidc-preview.compose.yml \
  up --detach --no-deps --no-build --wait --wait-timeout 60 \
  app-fastapi-dev oidc-preview-tls
```

Do not use the base-only launcher to preserve OIDC settings: omitting the overlay
disables the feature. Do not use `down --volumes` to stop this preview.

Verified live: HTTPS root reaches the password form (200), healthz/readyz (200),
enabled token endpoint rejects empty requests (400 `invalid_request`), and UserInfo
rejects missing credentials (401). This is an activation smoke check, not a completed
user login or external GitLab/Cloudflare E2E.
