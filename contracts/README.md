# SSO migration contracts

This directory is the language-neutral compatibility boundary between the
current Express server and a replacement implementation. The runner treats both
servers as black boxes and never imports application source.

## Run the public baseline

Start both implementations, then run:

```sh
python3 contracts/bin/differential.py \
  --baseline http://127.0.0.1:4000 \
  --candidate http://127.0.0.1:4001
```

The default checked-in scenarios are read-only and contain no credentials or PII. A
non-zero exit code means that a response failed its contract or that the two
implementations differed after dynamic values were normalized.

To run one scenario or use a different scenario file:

```sh
python3 contracts/bin/differential.py \
  --baseline http://127.0.0.1:4000 \
  --candidate http://127.0.0.1:4001 \
  --scenario public.jwks
```

## Predicate format

Expected JSON and header values are ordinary JSON. A value may instead be one
of these deliberately small predicates:

- `{ "$predicate": "any" }`
- `{ "$predicate": "nonempty-string" }`
- `{ "$predicate": "uuid" }`
- `{ "$predicate": "timestamp" }`
- `{ "$predicate": "url" }`
- `{ "$predicate": "jwt", "claims": { ... } }`

Predicates validate shape and retain the actual value for differential equality;
they never make two different issuers, keys, claims, or state values equivalent.
For genuinely dynamic values, name them explicitly:

- `{ "$capture": "access-token", "$predicate": "jwt" }`
- `{ "$equalsCapture": "access-token" }`

Captured values normalize to their capture name. Reusing a capture within one
response also asserts equality.

Object fields are exact by default. Add `"$allowExtra": true` to an expected
object when forward-compatible extra fields are intentional. Arrays are exact
and ordered. JWT predicates decode (but do not cryptographically verify) the
header and claims. The `jwt-rs256-jwks` response assertion additionally verifies
the RS256 signature against the implementation's JWKS using only Python's
standard library.

## Run stateful fixtures

Stateful coverage is executable when isolated baseline and candidate fixture
adapters are available:

```sh
python3 contracts/bin/differential.py \
  --baseline http://127.0.0.1:4000 \
  --candidate http://127.0.0.1:4001 \
  --scenarios contracts/scenarios/fixtures.json \
  --baseline-adapter contracts/adapters/express_fixture.py \
  --baseline-adapter-config /secure/untracked/express-contract-env.json \
  --candidate-adapter /path/to/fastapi-fixture-adapter \
  --candidate-adapter-config /secure/untracked/fastapi-contract-env.json
```

The adapter protocol is documented in `adapters/README.md`. These scenarios
cover valid HS256 refresh rotation plus `none`, HS384, and HS512 rejection/no mutation, login plus JWKS signature
verification and refresh-ledger delta, recovery token deltas, and an admin state
transition.

## Run the shared-state core gate

After both isolated runtimes have been deliberately configured against the
same disposable PostgreSQL database and the same non-zero Redis logical
database, run the mixed-writer gate with one shared fixture adapter:

```sh
python3 contracts/bin/shared_state.py \
  --express http://127.0.0.1:4400 \
  --fastapi http://127.0.0.1:4401 \
  --fixture-adapter contracts/adapters/express_fixture.py \
  --fixture-config /secure/untracked/shared-contract-env.json \
  --jsonl /tmp/shared-state-core-v1.jsonl \
  --run-id local-shared-001 \
  --source-revision "$(git rev-parse HEAD)"
```

`shared-state-core-v1.json` fixes ten schedules at ten trials each. Seven
schedules use concurrent actors waiting on one in-process release barrier. For
those 70 trials, the runner fails closed unless at least one Express request
lifetime overlaps one FastAPI request lifetime in monotonic time. This is a
concurrent-ingress smoke check; it does not prove that database or Redis
critical sections overlapped. Every HTTP operation has one attempt and zero
retries. The runner stops after the first mismatch, emits the remaining planned
rows as `NOT_RUN`, and writes only sanitized counts, status classes, boolean
outcomes, and error digests. The JSONL file is created exclusively and made
read-only after it is flushed. Passing this 100-row gate does not satisfy the
full Phase 7 sample or make the replacement production ready; both fields
remain explicitly false.

The mixed failed-login schedule accepts a final failure count from 5 through
20 with the lock set. Both runtimes intentionally skip increments after a
request observes the lock, and an ingress-lifetime overlap cannot prove that all
20 requests read the credential before the lock was written.

## Password-flow development driver

`bin/flow_driver.py` executes the first two approved core flows over loopback HTTP:
direct password login/token and password handoff/exchange. It uses the existing
fixture adapter setup/snapshot/teardown protocol, so state assertions can be run
against disposable PostgreSQL/Redis without importing either application's code.
The local regression suite uses synthetic HTTP servers and fixture state, not live
production services. Run `--help` for the explicit runtime/config inputs.

These are development trials, not a controlled qualification collector or a load
generator. Its monotonic trial duration includes fixture lifecycle work and must not
be used as the performance profile's scheduled-to-completed sample latency.
Reports retain `qualifyingEvidence=false`; the manifest still marks nine
flows partial and the global limiter unsupported. Never import development results
as seven-gate PASS evidence.
Use only explicitly configured disposable runtimes, dev mail, test-named databases
and isolated nonzero Redis databases. Cross-runtime handoff needs shared fixture
stores; two independent databases cannot prove shared-state consumption.

Example for already prepared **disposable** runtimes (this command mutates fixture
state, so do not substitute production targets):

```sh
python3 contracts/bin/flow_driver.py \
  --express http://127.0.0.1:4400 \
  --express-adapter contracts/adapters/express_fixture.py \
  --express-adapter-config /secure/untracked/express-shared-fixture.json \
  --fastapi http://127.0.0.1:4500 \
  --fastapi-adapter contracts/adapters/fastapi_fixture.py \
  --fastapi-adapter-config /secure/untracked/fastapi-shared-fixture.json \
  --issuer https://auth.financenow.kr \
  --flow password-handoff-exchange --topology express-fastapi \
  --jsonl /secure/untracked/password-handoff-development.jsonl \
  --provenance runId=password-driver-development \
  --provenance sourceRevision="$(git rev-parse HEAD)"
```

Both config files must be regular0600 files with explicit adapter guard variables,
store URLs and synthetic runtime refresh secrets from `adapters/README.md` (including
the FastAPI acknowledgement in its config). Shell credentials/guard flags do not fill
missing config. Mixed topologies require matching isolated store URLs and distinct
runtime origins. Use `fastapi-express` for reverse handoff or a single runtime topology
with `password-direct-login-token`. Source provenance is caller-declared development
metadata, not authenticated source attestation. Run only against the stated source;
do not label dirty or differing runtime code as clean same-SHA qualification.

The manifest binding in `performance/profile-v1.json` was refreshed when the driver
was added, when its four implemented password/mail flows were explicitly mapped,
and when the separate Google mixed-only dispatch was recorded.
All numeric thresholds, flow order and load settings are unchanged.
Old manifest/profile-bound measurement plans and evidence are invalid for the new
corpus; generate a fresh plan, never rewrite historical evidence hashes. A future
reviewed profile-v2/p50 policy is still required before final performance collection.

Local verification (uses the already locked development environment):

```sh
uv run --locked --project fastapi-auth-server pytest -q contracts/tests/test_flow_driver.py
uv run --locked --project fastapi-auth-server pytest -q contracts/tests
```

### Connected Google mixed-runtime development trial

The common `bin/flow_driver.py` entrypoint accepts `--flow oauth-google` only as
an exclusive invocation with `--oauth-google-launch-config`. It calls the fixed
owned-runtime launcher in-process, so interrupts and failures traverse the
launcher's bounded cleanup instead of abandoning its child process groups or
private provider-record pipe. Password/runtime adapter arguments, `--topology`,
private-mail configuration and caller-declared `--provenance` are refused in this
mode; runtime roles, origins and the expected issuer come only from the same-owner
mode-0600 launcher config validated by `bin/private_oauth_flow_launcher.py`.

```sh
python3 contracts/bin/flow_driver.py \
  --flow oauth-google \
  --oauth-google-launch-config /secure/untracked/google-mixed.json \
  --jsonl /secure/untracked/google-mixed-development.jsonl
```

The output preserves the Google launcher's native single-result shape and must
remain `qualifying=false`. Only `express-fastapi` and `fastapi-express` are
supported. The explicit `provider-error-state-lifecycle` item remains unverified,
and the path does not prove the approved independent per-runtime corpus, live
disposable PostgreSQL/Redis execution, repeated samples, authenticated source
identity or any Phase 7 gate. The common entrypoint never turns that development
result into a uniform core-flow trial or adds Google to the existing four-flow
`FLOWS` corpus.

### Connected private-mail development trials

The same driver also accepts `email-verification-attach-handoff-exchange` and
`password-reset-session-revoke`. Run mail flows in a separate invocation from
password-only flows, with `--private-mail-launch-config /secure/untracked/mail.json`.
This is a new owned-runtime launch, not permission to attach to an existing server.
Both adapter configs must explicitly select
`CONTRACT_SERVER_MAIL_MODE=private-loopback-smtp`; all disposable-store guards
still apply. The launcher supplies private STARTTLS capture and CA/session settings.

The launch file must be a same-owner regular mode-0600 JSON file with `version: 1`,
an explicit `runId`, a `recipients` object mapping fixture user IDs to their synthetic
mail addresses, and a `runtimes` object with `express` and `fastapi` entries. Each
runtime entry supplies an argument-list `command`, an existing absolute `cwd`, and
a loopback `healthUrl` matching that runtime's CLI origin. Commands and fixture
configuration are operator-supplied for disposable runtimes; there are no production
defaults. Both pending and attachment identities must be in the recipient map.

The launcher verifies ownership of the actual health-request connection before
sending the request, drains its owned process groups, and removes private material.
This does not provide namespace containment or authenticated runtime code identity.
Rows retain `qualifyingEvidence=false`; cleanup failure produces a failed row.
The separate-process role regression uses hermetic HTTP/SQLite test implementations,
not the real Express/FastAPI engines or a shared PostgreSQL/Redis qualification run.
Do not count these tests as completing A02/A03 or any live gate.

## Evaluate Phase 7 performance evidence

`performance/profile-v1.json` is the frozen, SHA-256-bound offline performance
contract for the ten approved core flows. It requires ten epochs, alternating
five Express-first and five FastAPI-first, with 20 excluded warmups and exactly
100 measured trials per flow/runtime/epoch (80 success and 20 expected-failure
trials). The committed load is open-loop at 20 requests/second, a 5,000 ms
timeout, and at most 16 in flight. Overrides, retries, and outlier removal are
not accepted, and any unexpected transport, timeout, malformed, 5xx, or aborted
outcome in an otherwise complete sample is an absolute failure.

Generate the deterministic 20,000-row measurement identity plan (not qualifying
evidence), or evaluate a completed evidence document:

```sh
python3 contracts/bin/performance.py generate-plan --output /tmp/performance-plan.json
python3 contracts/bin/performance.py evaluate \
  --input /secure/untracked/performance-evidence.json \
  --output /tmp/performance-result.json
```

The evaluator performs no HTTP or load generation. It validates exact sample
identity/order/counts, warmup exclusion, reset proof, provenance and profile /
manifest hashes before computing scheduled-to-completed nearest-rank p95. It
binds every reset boundary to the next block's first scheduled timestamp and
rejects the block unless every request from the preceding block has completed.
It reports observed rows separately from rows accepted by all structural checks,
so oversized or otherwise malformed submissions remain visible without making
the result schema invalid; the observed counter is capped at the same numeric
32 MiB boundary and records whether capping occurred. It
uses integer comparisons for per-flow and aggregate p95 (FastAPI at most 120%
of Express), comparative error increase (at most 10/1000 in addition to the
zero-unexpected-outcome integrity gate), and login-success decrease (at most
20/1000). Missing or malformed proof is `INCOMPLETE`; a complete threshold
violation is `FAIL`; otherwise it is `PASS`. Every result retains
`overallReplacementReady=false` and never authorizes traffic changes.
Because reset, warmup, and provenance values are submitted claims that an
offline evaluator cannot independently observe, results also retain
`qualifyingEvidence=false` until a separately controlled launcher binds and
attests those events. Evaluator input is capped at 32 MiB before JSON decoding.

## Files

- `manifest.json` maps migration behavior to scenarios, schemas, snapshots, and
  current implementation evidence.
- `scenarios/public.json` is the executable, non-mutating HTTP baseline.
- `scenarios/shared-state-core-v1.json` is the approved mixed-runtime shared-store schedule matrix.
- `performance/` contains the frozen Phase 7 performance profile and exact evidence/result schemas.
- `schemas/` contains JSON Schema definitions for shared wire/state shapes.
- `snapshots/` contains synthetic examples only. Values use reserved domains and
  obvious placeholders; they must never be replaced with production captures.
- `tests/` exercises the comparison runner against local stub servers.

## Test the runner

```sh
python3 -m unittest discover -s contracts/tests -v
```
