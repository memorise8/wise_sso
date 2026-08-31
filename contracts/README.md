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

## Files

- `manifest.json` maps migration behavior to scenarios, schemas, snapshots, and
  current implementation evidence.
- `scenarios/public.json` is the executable, non-mutating HTTP baseline.
- `schemas/` contains JSON Schema definitions for shared wire/state shapes.
- `snapshots/` contains synthetic examples only. Values use reserved domains and
  obvious placeholders; they must never be replaced with production captures.
- `tests/` exercises the comparison runner against local stub servers.

## Test the runner

```sh
python3 -m unittest discover -s contracts/tests -v
```
