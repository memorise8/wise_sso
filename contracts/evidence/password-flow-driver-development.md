# Password-flow driver development checkpoint

Scope: approved replacement plan M1 first vertical slice, not full M1 or Phase7 qualification.
Baseline: `e32044814464b8c3e4716a9196964b37bbf8b7ed`.
Replacement verdict: **NOT_READY**.

## Implementation

- `contracts/bin/flow_driver.py`: direct password login and cross-runtime handoff trials
  using HTTP and the existing fixture adapter protocol; no application imports.
- Local tests use synthetic loopback HTTP endpoints and fixture state. They do not run
  real Express/FastAPI processes with PostgreSQL/Redis or authenticate collector evidence.
- `contracts/bin/differential.py`: shared RS256 verifier rejects non-modulus-sized and
  out-of-range signatures, ambiguous key IDs and RSA keys below2048 bits.
  The malformed-signature regression failed before the fix and passed after it.
- Manifest remains nine partial flows and one unsupported flow. New driver metadata
  explicitly forbids qualification/full-sample/replacement promotion.
- Profile-v1 changed only its manifest binding. Numeric policy, flow order and load
  shape match baseline exactly. Old manifest/profile hash evidence is rejected;
  a new20,000-row identity-only development plan was generated locally (not measurements).

## Verification

- Final FastAPI suite:1021 passed,79 skipped; existing Starlette deprecation warning.
- FastAPI Ruff check/format and existing four security modules' strict mypy: PASS.
- Manifest/performance regressions after binding update:23 passed,106 subtests passed.
- Driver:14 passed,17 subtests passed; covers local HTTP, subprocess CLI, both mixed
  directions, token/header/body/redirect defects and cleanup failures. A delayed HTTP
  mutation after client timeout leaves cleanup `not-proven`, never PASS.
- Combined contracts after exact JSON media-type hardening:107 passed,146 subtests
  passed (28.42s). Mislabelled `text/notjson` is rejected by a regression that failed
  before the media-type fix and passed afterward.
- New driver/test plus shared differential strict mypy: PASS. New driver/test Ruff
  check/format and other changed contract modules' Ruff checks: PASS.
- Independent architect (`flow_architecture_review`): CLEAR. Independent code reviewer
  (`flow_code_review`): APPROVE,11 files reviewed,0 outstanding findings. Synthesis:
  APPROVE for this first M1 slice only. The code-review workflow led to stricter body,
  redirect, cross-runtime routing, secret handling and timeout cleanup verification.
- Existing `test_differential.py` has10 pre-existing Ruff findings (PYI034/SIM117),
  confirmed against baseline. This slice does not introduce new findings there.

## Remaining work

Full10-flow corpus, approved repeated samples, real disposable runtime/store validation,
controlled collector, seven-gate same-SHA evidence and canonical refreeze remain open.
Runner/signer/bootstrap decisions and recovery/p50 policies remain unapproved.
Neither this document nor a development `pass` authorizes lock freeze, production
traffic changes, external publishing or Express retirement.
