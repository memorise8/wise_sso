# Fixture adapter protocol

Stateful scenarios use an external executable so the contract runner remains
independent of Express, FastAPI, Prisma, SQLAlchemy, PostgreSQL drivers, and
Redis clients. Each implementation/environment supplies its own adapter.

The runner invokes:

```text
adapter setup <fixture-name>
adapter snapshot <probe-name>
adapter teardown <fixture-name>
adapter expire <fixture-name>
```

The concrete Express adapter is `express_fixture.py`. The FastAPI candidate uses
`fastapi_fixture.py`, which shares the canonical fixture/probe implementation
and additionally verifies the Prisma-compatible schema before mutation. Both
use only black-box HTTP, the `psql` executable, and a dependency-free Python
RESP client for Redis; neither imports or executes application source. Run the
applicable safety check before a suite:

```sh
contracts/adapters/express_fixture.py preflight express
contracts/adapters/fastapi_fixture.py preflight fastapi
```

`CONTRACT_BASE_URL` contains the server URL. Every invocation writes exactly one
JSON value to stdout and exits zero. Diagnostics go to stderr. `setup` returns
an object containing synthetic request values referenced by `$fixture` in
`scenarios/fixtures.json`. `snapshot` returns a canonical, language-neutral
state projection. `teardown` returns any JSON value after removing only records
owned by that deterministic fixture.

Required fixtures and fields:

- `active-user-refresh-none`, `active-user-refresh-hs256`,
  `active-user-refresh-hs384`, and `active-user-refresh-hs512`: `refreshToken`,
  `algorithm`, `audience`, and active-user claims. Every token has a matching
  active ledger row. HS256 must rotate successfully; HS384/HS512 use the same
  isolated secret but must be rejected; `none` retains unsigned rejection.
- `active-password-user`: `email`, `password`, `name`, `roles`, `audience`.
- `pending-email-user`: pending-user identity, password, audience/roles,
  client/redirect/state/PKCE fields, and mandatory `attachUserId`/`attachEmail`
  for the separate pending-password attachment target.
- `admin-and-active-target`: `authorization`, `targetStatusPath`.

Required probes:

- `refresh-ledger`: counts plus sorted `activeTokenHashes` and
  `revokedTokenHashes`, making any permissive rotation visible.
- `auth-lifecycle`: active refresh count, sorted active token hashes for internal
  token-to-ledger linkage, and auth-handoff key count. The runner never publishes
  the hashes.
- `pending-email-auth-lifecycle`: the same projection scoped to the pending
  verification user, not the unrelated active-password fixture user.
- `password-reset-ledger`, `email-verification-ledger`, and
  `attach-email-verification-ledger`: `unusedTokens` and sorted `digests` for
  unexpired unused tokens, scoped to the active, pending, and attachment users
  respectively. Hashes are internal token-to-ledger assertions, not public output.
- `email-verification-result`, `pending-password-attach-result`, and
  `password-reset-result`: identity-specific persisted state after confirmation;
  the driver also checks exact known-active refresh hashes become revoked.
- `email-verification-audits` and `password-reset-audits`: counts scoped to the
  fixture identities and expected failure reasons.
- `target-user`: `{ "status": "ACTIVE" | "SUSPENDED" | ..., "auditEvents": number }`
- `shared-rate-limit`: sanitized shared Redis counter counts and positive TTLs;
  raw keys and client addresses are never returned.
- `failed-login-ledger`: failed-login count, whether the lock was set, and the
  active refresh-token count for the synthetic active user.
- `fixture-anonymous-audits`: count of only the anonymous `/auth/login`
  rate-limit, `/auth/exchange` invalid-code, and refresh-failure audit shapes
  plus the anonymous successful logout shape produced when refresh wins the
  logout/refresh race. Teardown must reduce it to zero after every trial.

The shared-state core runner uses one adapter/config because both runtimes must
write the same disposable PostgreSQL database and Redis logical database. It
overrides `CONTRACT_BASE_URL` only for adapter protocol compatibility; setup and
the shared probes do not select separate stores per runtime. This topology is
different from the independent-runtime differential gate, which requires two
adapter configs and two isolated store pairs.

## Adapter environment

All three service URLs must use loopback hosts. The PostgreSQL database name
must contain a distinct `test`, `contract`, or `fixture` segment and cannot be
`auth_db`. Redis database 0 is forbidden.

- `CONTRACT_FIXTURE_MODE=1` — explicit destructive-fixture acknowledgement.
- `CONTRACT_FASTAPI_RUNTIME=1` — additional acknowledgement required only by
  `fastapi_fixture.py`; prevents accidentally selecting it for another runtime.
- `CONTRACT_SERVER_MAIL_MODE=dev` — asserts the isolated server is configured
  with `MAIL_PROVIDER=dev`. Connected mail trials instead explicitly select
  `private-loopback-smtp` and require a binding issued by the owned private-mail
  launcher. A caller-authored mode flag alone does not authorize SMTP fixtures.
- `CONTRACT_REDIS_ISOLATED_DB=1` — explicit acknowledgement that the selected
  non-zero Redis logical database is reserved for this contract run.
- `CONTRACT_REFRESH_SECRET` — required untracked value exactly matching the
  isolated server's `JWT_REFRESH_SECRET`. It must be at least 16 characters and
  cannot be a known example/test placeholder. The adapter never prints or
  returns it.
- `CONTRACT_BASE_URL` — isolated Express URL, for example
  `http://127.0.0.1:4400`.
- `CONTRACT_DATABASE_URL` — isolated PostgreSQL URL, for example
  `postgresql://fixture:...@127.0.0.1:5432/auth_contract_test`.
- `CONTRACT_REDIS_URL` — isolated Redis URL using DB 1 or higher, for example
  `redis://127.0.0.1:6379/9`.
- `CONTRACT_FIXTURE_EMAIL_DOMAIN` — optional synthetic email domain; defaults to
  `example.invalid`. Set it to the isolated server's allowed company domain if
  `COMPANY_ALLOWED_EMAIL_DOMAIN` is enabled.
- `CONTRACT_FIXTURE_AUDIENCE` — optional token audience; defaults to
  `contract-fixture`.
- `CONTRACT_FIXTURE_CLIENT_ID` — optional registered SSO client; defaults to
  `contract-fixture`.
- `CONTRACT_FIXTURE_REDIRECT_URI` — optional registered loopback redirect URI;
  defaults to `http://127.0.0.1:4101/auth/callback`. Configure this as a second,
  fixture-only client in the isolated server's `AUTH_CLIENTS_JSON`; do not reuse
  the production-shaped `temis` client with an incompatible loopback redirect.

The fixed password, Argon2id hash, UUIDs, names, and default `.invalid` emails
are synthetic test constants. HMAC fixtures use only the required untracked
isolated-server secret. The adapter deletes only
those UUIDs/emails/audit reason and clears known WiseAcct prefixes only inside
the preflight-approved isolated Redis database.

`expire` is limited to the supported verification/reset fixture tokens; it
changes their expiration in the same guarded disposable store for deterministic
expired-token rejection. It is not a general SQL or production maintenance API.
Private-mail launch bindings tie the session capability, runtime identity/PID,
health origin and CA hash together. The launcher supplies the SMTP and CA settings;
do not put forged session/capture values in adapter configuration. These local
bindings are development ownership checks, not authenticated qualification evidence.

For two isolated implementations, pass separate untracked JSON environment
files with `--baseline-adapter-config` and `--candidate-adapter-config`. Each
file is a flat object of the variables above. Keep files containing database or
Redis passwords outside the repository with restrictive permissions. The runner
overrides `CONTRACT_BASE_URL` with the corresponding `--baseline` or
`--candidate` URL.

Adapters must point at isolated fixture databases and Redis namespaces. They
must not use production credentials or mutate a shared/production store. The
runner deliberately does not provide default database credentials or service
targets. The FastAPI adapter remains unusable until an isolated environment is
explicitly supplied and its Prisma-compatible schema passes preflight.
