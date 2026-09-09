# A05 common Google dispatch - development only

The canonical `contracts/bin/flow_driver.py` CLI now routes the explicit
`oauth-google` selection to the fixed `private_oauth_flow_launcher.py` entrypoint.
The launcher is loaded and called in the same Python process so `KeyboardInterrupt`
and other `BaseException` paths still cross its owned-runtime context manager and
bounded cleanup. The dispatcher does not wrap the owner in a subprocess timeout.

This mode is deliberately exclusive. It refuses password/runtime adapter inputs,
mail configuration, topology overrides, multi-flow selection and caller-declared
provenance. The same-owner mode-0600 launcher config remains the only source of the
two disposable runtime commands, distinct loopback origins, roles, expected issuer,
fixture adapter and synthetic environment. The common driver validates and writes
the launcher's native result without manufacturing a `core-flow-trial` record.

The output stays `qualifying=false` and carries
`unverified=["provider-error-state-lifecycle"]`. Only `express-fastapi` and
`fastapi-express` execution is supported. Independent per-runtime Google cases,
actual Express/FastAPI execution on disposable PostgreSQL/Redis, approved repeated
samples and authenticated same-source collection remain open. This does not satisfy
A05 or promote any Phase 7/READY flag.

The manifest records this as a separate mixed-only binding instead of adding Google
to the four-flow `FLOWS` tuple. Updating the manifest invalidates the old v1
manifest binding, so `performance/profile-v1.json` is rebound to the new manifest
bytes only. Performance flow order, counts, load and thresholds are unchanged.

Final independent review: code APPROVE + architecture CLEAR for this bounded
development checkpoint only. Frozen leader contracts regression: 236 passed and
202 subtests passed; all 11 code/test files plus manifest/profile hashes were
unchanged across the run. Ruff check/format and strict mypy passed for all 11 files.
The launch policy requires `CONTRACT_FASTAPI_RUNTIME=1` for full schema preflight
and rejects fixture interpreter/loader overrides. See
`python-ready-baseline.md` for environment evidence and remaining READY blockers.
