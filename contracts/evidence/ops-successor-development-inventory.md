# R04 development inventory — no operational ownership transfer

Inspected against source baseline `606581a` and `writer-surface-inventory.json`.
All 14 background-maintenance inventory IDs are represented below. Current Express
and Prisma ownership is unchanged; R04 is not code-complete or live-verified.
Paths to Python modules below are relative to `fastapi-auth-server/src/`.

| Inventory ID | Existing candidate / retained tool | Remaining verification or decision |
|---|---|---|
| job.tokens-cleanup | `wiseacct_sso/ops/refresh_cleanup.py` | Existing `python -m` entrypoint/unit tests; disposable integration, schedule and single owner unverified |
| job.audit-cleanup | `wiseacct_sso/ops/audit_cleanup.py` | Existing `python -m` entrypoint/unit tests; retention approval, integration and single owner unverified |
| job.grant-admin | `wiseacct_sso/ops/first_admin.py` | Existing `python -m` entrypoint/unit tests; controlled operator invocation and integration unverified |
| job.backfill-default-roles | Dormant `wiseacct_sso/ops/default_role_backfill.py`; Express script remains active owner | Atomic serializable candidate preserves existing roles and configured TEMIS default; unit/SQL tests only, disposable integration and owner transfer unverified |
| job.merge-split-identities | Dormant `wiseacct_sso/ops/merge_split_identities.py`; Express script remains active owner | Default dry-run, explicit apply, per-candidate atomic revalidation and Prisma timestamp/cascade parity covered by unit/SQL tests; disposable integration and owner transfer unverified |
| job.qa-seed-admin-flow | Express test-only fixture | Not a production successor; keep disposable-only boundary |
| job.prisma-migrate-dev | Prisma | Sole schema source remains Prisma; migration owner packaging required before Express toolchain removal |
| job.prisma-migrate-deploy | Prisma | Same sole schema owner; no Python runtime DDL |
| job.prisma-studio | Prisma interactive writer | Fence during maintenance; no replacement/activation authorized |
| job.provision-current-server-db | Express ops provisioning script retained | Infrastructure ownership and grants remain separate approval scope |
| job.init-local-postgres | Existing disposable initialization | Not a production successor; do not run against current services |
| job.restore-test-db | Existing disposable restore; R01 development collector | R01 has no authenticated backend, gate consumer, smoke or frozen recovery policy yet |
| job.phase0-integration | Existing disposable integration workflow | Not a production successor; isolation and cleanup remain mandatory |
| job.compose-volume-delete | Existing destructive operator surface | Must remain fenced; this inventory does not authorize volume deletion |

Also retain `auth-server/package.json` commands `ops:backup` and `ops:restore-test`:
the new R01 development collector is not yet their production replacement. Backup
retention, encrypted artifact recovery, policy and actual restore evidence are open.

The dormant module boundary is explicit in `wiseacct_sso/ops/__init__.py`. Existing
unit coverage is in `tests/unit/test_{refresh_cleanup,audit_cleanup,first_admin,default_role_backfill,merge_split_identities}_ops.py`;
`tests/static/test_no_database_ddl.py` preserves the runtime/schema boundary.

Before cutover, discover external cron/systemd/CI/operator writers in addition to
this repo inventory. Apply `STOP_BACKGROUND_OPS_WRITERS` and the existing 12-stage
drain in `ingress-capabilities.md`; prove zero old jobs/processes/leases and exactly
one approved new background owner. No checked-in schedule or live ownership proof
was found in this inspection. Do not infer owner transfer from a module existing.
