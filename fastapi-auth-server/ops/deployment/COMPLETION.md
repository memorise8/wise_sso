# Same-server Express → FastAPI completion checkpoint

Date: 2026-09-18. Status: **NOT_READY / deployment preparation only**.

## Scope

Finish the existing migration, not a rewrite using `temis-sso-lab`. Keep existing
user data and Prisma-owned tables. No production service, credential, DB, Redis,
ingress or schema was changed during this checkpoint. No new automated tests were
added or executed; the user previously reserved the integration-test decision.

The historical seven-gate acceptance policy remains unchanged. This practical
checklist separates application/deployment work from formal qualification; it is
not an alternative way to publish READY or bypass an unfrozen toolchain.

## Read-only observations on this host

- `auth-server-app-1` is running and healthy; published at `192.168.0.4:4000`.
- `auth-server-postgres-1` and `auth-server-redis-1` are running and healthy;
  published on loopback ports 5432 and 6379 respectively.
- All three belong to `auth-server_default`.
- No TCP listeners on 4001 or 4002 were observed at inspection time. This is not
  a reservation and must be rechecked before a future launch.
- Nginx is installed, but the inspected enabled-site/conf.d configuration did not
  identify an SSO upstream to port 4000. The public ingress owner/location remains
  unknown; an installed Nginx binary does not prove it serves the SSO hostname.
- No container environments or private credential files were read. Database role
  privileges, actual provider activation and mail settings remain unverified.

## What already exists

The FastAPI runtime wires PostgreSQL, Redis, password/JWT services, provider
clients, real mail transports and admin routes. Its startup does not migrate the
schema. The Dockerfile uses a non-root user and starts the Uvicorn application
factory on port 4001. `/healthz` is liveness; the updated `/readyz` checks both DB
and Redis using live pings. Neither endpoint alone proves login or cutover readiness.

The existing development Compose intentionally creates isolated stores. It must
not be repurposed to attach production volumes. A separate app-only dormant
candidate is included alongside this checklist; it does not replace the
guarded development launcher or controlled image-build path.

## Remaining work, in dependency order

| Step | Work / completion evidence | Current status |
| --- | --- | --- |
| 1. Deployment package | App-only configuration; explicit image/env/network; loopback candidate port; readiness; no schema/store creation | Dormant configuration, not launched |
| 2. Environment continuity | Privately map DB role, Redis, signer/JWK/kid, issuer, audience, client policies, OAuth callbacks and real mail; preserve existing identities | Not verified; no secret reads |
| 3. Ingress and client IP | Identify actual public ingress; define reachable candidate address, trusted proxy boundary and limiter identity; document exact reversal | Opt-in trusted-proxy code implemented; actual ingress owner/location unknown |
| 4. Runtime verification | Approved isolated same-host resources; candidate startup, separate DB/Redis checks and essential existing-client flows | Not performed in this checkpoint |
| 5. Qualification | Finish existing security, performance, recovery, rollback and same-source acceptance requirements | Incomplete; no waiver implied |
| 6. Cutover | Explicit production decision, known-good Express fallback, route switch and observation | Not authorized or executed |

### Client-IP blocker

The Dockerfile and production entrypoint disable server-level proxy processing.
Application-level `TRUSTED_PROXY_IPS` now provides an opt-in, explicit IP/CIDR
allowlist before rate limiting. Empty configuration preserves socket-peer behavior;
wildcards, hostnames and universal `/0` networks are rejected. The actual proxy
hop and its forwarding-header sanitization still need to be identified before
selecting production values. Code availability is not proof of the deployed trust
boundary or equivalent client-IP behavior.

### DB and session continuity

Reusing the existing DB is the intended path, not exporting users to the Lab's
schema. Preserve Prisma migration ownership, existing credentials and required
DML permissions. In a container, `127.0.0.1` refers to that container, not the host
DB; the approved deployment must use the correct existing-network endpoint.
Preserve JWT signing material and client contracts if sessions are to survive.
Sharing Redis means sharing state and limiter effects; attaching a candidate is
not an isolated test simply because its HTTP port is private.

### Stop boundary and rollback

Do not load production credentials, attach/start the candidate on the operating
network, change public routing, stop Express, or apply DDL as part of this dormant
preparation. Those are separate production actions requiring a clear decision.
Routine rollback should restore routing to the retained Express instance; it must
not automatically restore an older DB backup and discard intervening user writes.

## Next required information

Identify where the public SSO hostname is routed to `192.168.0.4:4000` (for example,
an external gateway, reverse proxy or tunnel) and who owns that configuration.
This determines whether a host-loopback candidate is reachable and how client-IP
trust can be implemented. Do not guess or alter this host's unrelated Nginx sites.

## Static validation performed

Compose configuration parsing passed with a cleared process environment, an
explicit `/dev/null` interpolation env file, synthetic image/network values and
`config --no-env-resolution --quiet`. The all-zero image digest used for parsing
is a non-runnable validation placeholder, not a verified artifact. No image pull,
build, container creation, credential-file read or network attachment occurred.
This proves configuration syntax only, not image availability or runtime behavior.

## Runtime implementation continuation

- Added `python -m wiseacct_sso.runtime check|serve`: production-only settings
  validation, secret-safe errors, explicit serving action and configured `PORT`.
  Check mode makes no service connections and is not a READY verdict.
- Connected the candidate Compose command to this entrypoint; the default
  development Dockerfile command is unchanged.
- Added opt-in trusted-proxy middleware using the existing pinned Uvicorn package.
- Added read-only Redis PING to runtime readiness, including recovery after a
  transient failed probe without restarting/closing the client pool.
- Changed-file Ruff and mypy checks are the available implementation evidence.
  No new regression tests, live runtime or production integration checks were run.
