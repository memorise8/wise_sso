# Dormant FastAPI deployment candidate

Status: **NOT_APPROVED / NOT_READY**

`compose.candidate.yml` is an inactive, app-only description for a future
same-server FastAPI candidate. It does not start PostgreSQL or Redis, create
volumes, build an image, run migrations, change ingress, or authorize a
cutover. The service is behind the non-default `candidate-not-approved`
profile so an ordinary Compose invocation does not start it.

This file is deployment wiring, not Phase 7 evidence. Do not use a manual
Compose start, profile override, ad-hoc image, or ambient production Docker
access to bypass qualification or approval.

The Compose required-value expressions check only that variables are present.
They do not validate image-reference syntax, digest provenance, whether the env
path is absolute/private, or whether an operator is authorized. The profile and
`NOT_APPROVED` labels are visible guardrails, not a security or approval
enforcement boundary; the approved deployment procedure must enforce every
prerequisite below before it invokes Compose.

## Candidate boundary

The candidate has the following fixed properties:

- A prebuilt immutable image is required through
  `WISEACCT_FASTAPI_CANDIDATE_IMAGE`. The value must be the qualified registry
  reference in `repository@sha256:<64 lowercase hex characters>` form. A tag,
  local image name, or mutable digest alias is not acceptable.
- The image is neither built nor modified by this Compose file. Its Dockerfile
  supplies UID/GID `10001`. The candidate uses `python -m wiseacct_sso.runtime
  serve --host 0.0.0.0`, which validates production settings before starting
  Uvicorn, honors `PORT`, disables access logs/server headers and sets
  `proxy_headers=False`. The non-root user is unchanged. The image must contain
  this entrypoint; an older image is not compatible with this candidate command.
- Only container port `4001` is used. It is published on loopback host port
  `4002` by default, avoiding Express `4000` and the FastAPI development port
  `4001`. Changing the host port requires an explicit conflict check and does
  not approve public ingress.
- The filesystem is read-only except for an ephemeral, non-executable `/tmp`.
  All Linux capabilities are dropped and `no-new-privileges` is enabled. No
  privileged mode, host path, Docker socket, secret mount, or persistent volume
  is present.
- The health check calls `/readyz` through Python's standard library with
  proxy discovery disabled. `/readyz` includes live database and Redis readiness
  check; it is not replacement qualification or a cutover signal.
- The only network is the explicitly named existing external network. The
  actual network name and the PostgreSQL/Redis DNS names reachable from it
  must be confirmed on this server before any approved launch. This file does
  not attach or reconfigure the existing data services.

## Private environment prerequisite

`WISEACCT_FASTAPI_CANDIDATE_ENV_FILE` must be an absolute path to a separately
managed, private production environment file outside this repository. It must
not be a symlink, must be readable only by the deployment operator, and must
never be committed or copied into qualification evidence. Compose cannot prove
these path and permission requirements by itself; the approved deployment
procedure must fail closed when they are not met.

The environment must satisfy the production validation in
`wiseacct_sso.config.Settings` and preserve the current Express contracts:

- `DATABASE_URL` points to the existing production PostgreSQL database and
  Prisma-owned schema used by Express. Use the approved restricted application
  role with the required DML rights; do not give the FastAPI process the Prisma
  migration-owner credential. This candidate performs no DDL or migration.
- `REDIS_URL` points to the approved existing Redis endpoint and logical
  database needed for continuity of shared OAuth state and rate-limit data.
  Do not silently switch to a fresh Redis database during cutover.
- `JWT_ACCESS_ALGORITHM`, `JWT_ACCESS_PRIVATE_KEY`,
  `JWT_ACCESS_PUBLIC_JWK`, `JWT_ACCESS_KEY_ID`, `JWT_REFRESH_SECRET`,
  `JWT_ISSUER`, and `JWT_AUDIENCE` match the currently approved signing and
  verification contract. The private key, public JWK, and key ID must match;
  synthetic development material is rejected in production.
- `AUTH_CLIENTS_JSON`, `CORS_ALLOWED_ORIGINS`, and
  `FRONTEND_REDIRECT_URL` retain the approved relying-client policy and public
  origins. The mandatory TEMIS client contract is validated at startup.
- `OAUTH_ENABLED_PROVIDERS=google,naver,kakao` is explicit when all three are
  intended to remain live. Supply the corresponding `*_CLIENT_ID` and
  `*_CLIENT_SECRET` values. `GOOGLE_REDIRECT_URI`, `NAVER_REDIRECT_URI`, and
  `KAKAO_REDIRECT_URI` must remain the existing public callback URLs registered
  with each provider; do not substitute loopback, port `4002`, or a new path.
- `MAIL_PROVIDER` is a real `smtp` or `resend` provider, with its required
  credentials and approved `MAIL_FROM`/`MAIL_REPLY_TO`. Production validation
  rejects the development mail capture provider.
- `NODE_ENV=production` and container `PORT=4001` are deliberately enforced by
  Compose rather than trusted to the private file.

The exact production values and network endpoint are deployment inputs, not
defaults to infer from `.env.example`.

## Mandatory proxy and client-IP decision

Both launch paths disable Uvicorn's automatic proxy handling. The application
accepts an explicit comma-separated `TRUSTED_PROXY_IPS` allowlist of IP addresses
or CIDRs; its default is empty. Hostnames, wildcard trust and universal `/0`
networks are rejected. Do not substitute `FORWARDED_ALLOW_IPS` for this setting.

When configured, application proxy middleware runs before rate limiting and
request logging. Only allowlisted socket peers can supply forwarded client
information. Use exact proxy addresses where possible: trusting a Docker subnet
also trusts every other container in that subnet. The ingress must sanitize
forwarding headers; the application cannot establish the authenticity of a
client address asserted by an allowed but misconfigured proxy.

The code path now exists, but cutover remains blocked until the actual ingress
topology and socket peer are identified and its narrow allowlist is reviewed.
Leaving the setting empty behind a proxy may collapse users into the same
rate-limit bucket. No production proxy address is selected by this directory.

## Connection-free configuration check

With the intended settings already injected into the process environment, run:

```sh
python -m wiseacct_sso.runtime check
```

This command requires `NODE_ENV=production` and uses the application's Settings
validation. It does not load `.env`, connect to DB/Redis, send mail or contact
OAuth providers. It outputs only status and known top-level invalid field names;
validation messages, raw input, credentials and nested user-defined values are
not printed. Cross-field failures may have no field names. A valid result is
`CONFIG_VALID`, with `runtimeVerified=false` and `replacementReady=false`.
This is not a schema, connectivity, credential-validity or deployment approval
check. Do not expose private settings in shell history or committed files.

## Qualification and approval prerequisites

Replacement remains `NOT_READY`. A candidate launch or a healthy `/readyz`
does not change that status. All seven gates documented in
`../phase7/READINESS_BLOCKERS.md` must be completed with matching final-source
provenance:

1. `independent-contract`
2. `shared-state-core`
3. `performance`
4. `security`
5. `chaos`
6. `backup-restore`
7. `local-rollback`

Before an approved launch, also require the exact qualified image digest, the
validated private environment path, confirmed external-network reachability,
an unoccupied loopback candidate port, an ingress configuration review, real
OAuth/mail configuration, an approved change window, monitoring ownership, and
an explicit cutover/rollback decision. None is supplied by this directory.

For a configuration-only review, operators may render without starting the
profile, using synthetic non-secret substitutions and a synthetic private env
file. This repository intentionally provides no launch command; service start
and ingress changes belong to the approved deployment runbook after the gates
above pass.

## Cutover and rollback boundary

The eventual approved cutover must keep Express available, start the exact
candidate privately, verify health and contract checks, then switch only the
reviewed ingress target. Writer ownership, connection draining, session/token
continuity, and observable error/latency thresholds must be explicit in that
runbook.

Routine rollback means directing ingress back to the still-compatible Express
service, draining candidate traffic, and then stopping only the candidate after
the rollback checks pass. Because both runtimes use the existing database and
Redis state, **do not restore the database during routine application
rollback**: restoring would discard valid writes made after cutover. Database
restore is a separate disaster-recovery action governed by the approved backup
policy and evidence, not a normal version rollback step.
