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
