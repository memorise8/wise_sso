# GitLab CE × Wise SSO OIDC — local development handoff

Date: 2026-10-15. Base: `7fe5aeb`, the native FastAPI OIDC extension.
GitLab-specific work is on `feat/fastapi-oidc-gitlab`. No operational GitLab, Express,
Cloudflare, database, Redis, DNS, Tunnel or public routing configuration is changed.
This extension does not change the Express replacement's `NOT_READY` verdict.

## Updated compatibility decision

The 2026-10-14 conclusion described the old Express/custom `/auth/exchange` protocol.
It does **not** describe this branch: `/oauth2/authorize`, `/oauth2/token`, ID tokens,
UserInfo, S256 PKCE, Basic/Post client authentication and per-client authorization
already exist. Reuse them; no second GitLab authentication implementation is needed.

GitLab CE supports OIDC on Free Self-Managed. Use **manual endpoint configuration**
(`discovery: false`). The old `/.well-known/openid-configuration` remains deliberately
unchanged and is insufficient for GitLab automatic discovery. Do not set discovery
to true or silently augment the frozen legacy response. GitLab officially supports
explicit authorize/token/UserInfo/JWKS URLs.

## Supplied configuration examples

- [SSO client policy](../fastapi-auth-server/examples/gitlab/oidc-client.json)
- [SSO environment guidance](../fastapi-auth-server/examples/gitlab/oidc.env.example)
- [GitLab Omnibus snippet](../fastapi-auth-server/examples/gitlab/gitlab.rb.example)

These are **examples, not deployment files**. The client-secret hash placeholder
intentionally fails validation until replaced privately. Generate a separate high-entropy
client secret; store only its Argon2id hash at SSO and deliver the original privately to
GitLab. The GitLab example reads `WISESSO_GITLAB_CLIENT_SECRET` from its environment;
the future deployment must supply it securely. Never paste actual secrets into docs,
logs or version control. Merge this client into the full `OIDC_CLIENTS_JSON` array;
do not replace Cloudflare clients or modify legacy `AUTH_CLIENTS_JSON`.

| Item | Contract |
| --- | --- |
| Client ID / ID-token audience | `gitlab-temis` |
| Registered callback | `https://git.temis.me/users/auth/openid_connect/callback` |
| Required role | `gitlab:user` (explicit administrator grant only) |
| Released groups | Only `gitlab:*`; no Cloudflare/TEMIS role leakage |
| Scopes | `openid profile email` |
| Flow / PKCE | Authorization code / S256 |
| Token authentication | `client_auth_method: 'basic'`; body authentication is also supported |
| Token request scope | `send_scope_to_token_endpoint: false` — Ruby boolean, not string |
| Signature | `client_signing_alg: 'RS256'`, existing JWKS key and kid |
| Identity | `uid_field: 'sub'`, stable SSO user ID, not email or display name |
| Issuer | Exact configured SSO `JWT_ISSUER`; example assumes `https://auth.financenow.kr` |

The existing token endpoint deliberately rejects an unexpected token `scope` field;
the GitLab option suppresses it. Scope was already authorized and bound to the code.
Do not relax unknown-field checks or accept a scope upgrade just for GitLab defaults.
Endpoint URLs and issuer are separately configured: if the actual issuer differs from
the example, match it exactly without changing legacy token settings merely to fit
this snippet. HTTPS trust verification must remain enabled.

`sub` identifies the same user even if email/name changes. Both ID token and UserInfo
return the same sub and verified email; named accounts return name. Unnamed accounts
omit name rather than inventing a human name. GitLab account/profile handling for such
accounts must be included in the future full-instance pilot.

## Employee admission and account linking

SSO grants a code only to ACTIVE, email-verified users with `gitlab:user`. It repeats
that check at token exchange and UserInfo. Merely having a Wise SSO account, a company
email domain, or `agent-hub:user` is **not** permission to use GitLab. Required roles
are OR conditions; do not add `pending` or a broad common role as an alternative.
Use the existing administrator role API; this work does not grant anyone a role.

The example combines two controls:

1. SSO's explicit GitLab role admission.
2. GitLab JIT accounts are created **pending administrator approval**:
   `omniauth_allow_single_sign_on=['openid_connect']` and
   `omniauth_block_auto_created_users=true`.

If JIT creation is unwanted, set `omniauth_allow_single_sign_on=false` instead and
pre-provision/link existing accounts. `signup_enabled=false` alone is not a substitute
for an OmniAuth provisioning policy. Keep `omniauth_auto_link_user=false`; GitLab
19.4 guided linking requires proof of ownership of the existing GitLab account rather
than linking solely because email strings match. Do not auto-promote an SSO role to
GitLab administrator, group owner or project membership. No paid group-sync feature
is assumed in this CE integration.

These settings gate **new SSO authentication**, not every possible access channel.
Existing GitLab sessions, local password accounts, PATs, deploy tokens and SSH keys
are not revoked by removing the SSO role. Offboarding must separately block the
GitLab account/revoke credentials and sessions through an approved admin procedure.
Retain a controlled break-glass administrator while validating rollout; do not claim
the example alone enforces SSO-only access to all existing GitLab data.

## Remaining operational work — not executed

The handoff reports CE 19.4.1 at `/home/ruci/gitlab/compose.yaml`, current external URL
`http://192.168.0.4:8929` and SSH port 2224. These supplied facts were not used as
permission to inspect or change that deployment. DNS/Tunnel availability was reported
missing on 10/14; its present status is unverified.

After separate deployment approval:

1. Integrate/revalidate the feature on the canonical FastAPI release and make its
   approved HTTPS endpoints/JWKS reachable. Keep production issuer/key continuity.
2. Configure `git.temis.me` DNS/Tunnel/TLS and review GitLab external URL and proxy
   trust. The current IP/HTTP external URL does not match the proposed callback.
   Preserve SSH port 2224 and unrelated Compose settings; do not blindly replace YAML.
3. Register the exact HTTPS callback and privately provision the client secret/hash.
4. Merge the Omnibus provider/account policy snippet, reconfigure only in an approved
   maintenance window, and test with an explicitly authorized pilot employee.
5. Verify real browser login, denial for an unauthorized account, pending-user approval,
   guided account linking, unnamed/profile-change behavior, sign-out/relogin and
   offboarding including pre-existing sessions/PAT/SSH access. Review rollback before
   changing any existing login option.

## Local verification — 2026-10-15

- Full FastAPI regression: **1489 passed, 120 skipped** (one existing Starlette
  TestClient deprecation warning). Opt-in integrations are skipped in this run;
  the OIDC runtime scenarios were executed separately below.
- `./ops/run-oidc-integration.sh`: **2 passed**, Cloudflare and GitLab, using
  disposable loopback PostgreSQL/Redis and a real Uvicorn process. This covers
  permitted login, wrong client/callback/secret/PKCE, unauthorized/unverified/
  suspended users, code replay, signed claims, stable subject after profile changes,
  and role revocation at token exchange/UserInfo. Its temporary containers were removed.
- `./ops/run-gitlab-oidc-probe.sh`: **PASS**, using local pinned image
  `sha256:9bbf2223cbbae4c78854a65094e7ee00a9464796b48257d3d0b716a2154278c4`.
  GitLab CE 19.4.1 packages `omniauth_openid_connect 0.8.0`, `openid_connect 2.3.1`
  and `rack-oauth2 2.2.1`. The isolated, read-only, network-disabled container has
  no production mounts. Real gems construct authorization/S256 PKCE (128-character
  verifier), Basic/body token and Bearer UserInfo requests using absolute endpoint
  URLs, retrieve JWKS through the configured URI with stubbed HTTP, and accept a
  synthetic ID token from the actual FastAPI signer. Bad signature, audience, issuer, nonce
  and expiry are rejected. HTTP transport is stubbed, not a real GitLab login.
- Ruff lint/format, mypy (134 files), shell syntax and `git diff --check`: passed.

The packaged OmniAuth strategy does not explicitly reject a mismatched UserInfo
`sub`; its verified ID-token claims take precedence during merging. The probe records
this limitation rather than claiming rejection. Wise SSO returns the same user ID
from both endpoints, as checked by the runtime scenario. No upstream gem was modified.

Reproduce from `fastapi-auth-server/` with the existing project virtual environment
and local images. The probe intentionally fails if its exact local image is absent;
it never pulls a replacement or uses the running GitLab container. All generated
token/key inputs come from checked-in synthetic `.env.example`, not operational secrets.

## Authoritative references

- [GitLab OIDC](https://docs.gitlab.com/administration/auth/oidc/): Free Self-Managed,
  manual endpoints, scopes, client authentication and PKCE.
- [GitLab OmniAuth](https://docs.gitlab.com/integration/omniauth/): JIT accounts,
  administrator approval, guided versus automatic email-based linking.
- [GitLab CE 19.4.1 dependency lock](https://gitlab.com/gitlab-org/gitlab-foss/-/blob/191678a37648bc14466c2bed346ed60eee7ddec6/Gemfile.lock).
- [Pinned OmniAuth OIDC strategy](https://github.com/omniauth/omniauth_openid_connect/blob/9b2a67d76d3b64b2baa363c47a464345049d7448/lib/omniauth/strategies/openid_connect.rb).

Real GitLab Rails/browser/DNS/TLS E2E has **not** been executed. Isolated SSO protocol
and packaged-client evidence are reported separately; neither qualifies production.
