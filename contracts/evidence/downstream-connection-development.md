# Downstream evidence-validator connection — development only

Date: 2026-09-10. Baseline: `44e761f`.

The existing top qualification shell now invokes a fixed Python dispatcher instead
of treating all five downstream gates as placeholders. Optional external sanitized
security and backup/restore bundles reach the existing gate implementations.
Published child result consistency and nonqualifying status are checked before
recording the five per-gate summaries after successful path preflight. Unsafe or
reused paths fail before publication; no complete summary set is claimed for such
refusals or publication errors. Missing input is not confused with invalid
input; an unsupported PASS or inconsistent exit code is rejected.

Security validation uses a private external detached source mirror bound to the
top runner's initial source revision/tree. This resolves the conflict between
in-repository output creation and the validator's strict clean-source requirement;
the original repository's cleanliness guard is not weakened. The mirror is not
authenticated isolation or the full G02 source-copy contract.

This connects validators, not live collectors. No scanners, backup/restore command,
DB/Redis operation, candidate runtime or production service was started. Performance,
chaos and local rollback execution paths remain missing. The active security lock,
backup policy, sample requirements and finalizer refusal are unchanged.

The user requested development first and deployment on the current server. The
future integration environment can use separately scoped test containers and
synthetic stores here; another physical server is not inherently required.
Controlled-collector trust and production cutover remain separate boundaries.

## Verification scope

The launcher tests execute the real top shell in a committed synthetic repository
with a stub independent contract gate and downstream process. They prove argument
forwarding, environment scrubbing and failure/incomplete handling, not a real
Express/FastAPI integration run. Dispatcher tests separately exercise fixed child
validators and malformed-result rejection. A complete, current-time security bundle
reaches the real source/provenance checks despite top evidence being present in
the original repository, and reports exactly `TOOLCHAIN_LOCK_UNFROZEN` and
`CONTROLLED_COLLECTOR_REQUIRED`. The source mirror is removed afterward.

## Final validation

- Targeted dispatcher and top-shell tests: **19 passed**.
- Full FastAPI suite: **1435 passed / 79 skipped**, one existing Starlette/httpx
  deprecation warning, 36.55 seconds. The four changed code/test hashes were identical
  before and after this run.
- Full Ruff/format: passed (159 formatted Python files).
- Configured mypy: passed (113 files); changed Python files also pass strict mypy.
- Shell syntax and `git diff --check`: passed.

The full-suite run exposed a new test's process-global umask leak. A test-only
fixture now restores it; the existing permission guard was not relaxed. No real
application/store integration or contract-suite rerun is claimed by this checkpoint.

Independent final review: `downstream_code_review` **APPROVE** and
`downstream_arch_review` **CLEAR**, zero unresolved findings in the eight-file
checkpoint. Contract asset checks additionally pass: 9 tests / 109 subtests.
Approval is for this connection only, not all remaining development or READY.
