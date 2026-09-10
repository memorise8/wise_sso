# Remaining replacement qualification work

Checked on 2026-09-06 against implementation baseline `e61d4e6`.
Replacement status remains `NOT_READY`. This is an implementation/environment
inventory, not gate evidence. A green unit suite does not satisfy live collection.

## Seven required gates

| Gate | Available implementation | Required before qualification |
| --- | --- | --- |
| independent-contract | Guarded disposable launcher and differential runner | Full approved corpus/sample/claim coverage and a fresh run from the final source SHA |
| shared-state-core | Disposable shared DB/Redis launcher; historical 100 trials, 70 overlaps | Full approved mixed-runtime sample/claim coverage and fresh provenance; historical smoke is insufficient |
| performance | Frozen profile, deterministic plan and offline evaluator | Controlled load generator with observed resets/warmups, exact 20,000 measured trial identities and authenticated same-SHA evidence |
| security | Offline gate/intake, check-only online controller, local execution-boundary infrastructure | Authenticated 11-subject toolchain and verifier, isolated daemon, default-deny egress, actual scans, verified provenance and cleanup |
| chaos | Qualification runner placeholder | Disposable process/DB/Redis failure injection, recovery assertions and controlled evidence |
| backup-restore | Synthetic encrypted evidence validator and sentinel contract | Selected RTO/RPO/retention policy, actual encrypted backup/restore in new test DBs and controlled evidence |
| local-rollback | Qualification runner placeholder | Disposable Express rollback rehearsal with session/state/writer/drain assertions and controlled evidence |

2026-09-10 connection update: `run-phase7-qualification.sh` invokes the fixed
Python downstream dispatcher. Explicit security/backup input bundles now reach
their existing validators and publish nested evidence. This is evidence validation,
not actual scanning/backup collection or authenticated qualification. Performance,
chaos and local rollback execution paths remain unimplemented in the dispatcher;
missing security/backup inputs remain distinct from invalid supplied bundles.
`finalize_qualification_group.py` unconditionally adds
`controlled-collector-required` and keeps `overallReplacementReady=false`.
Those restrictions must be replaced only alongside authenticated collection and
negative tests; deleting them to obtain a ready label is not completion.

Every final bundle must share the exact source SHA and version-2 provenance.
Do not edit historical smoke evidence into a new passing bundle. Canonical
refreeze/replay and original runtime prerequisite/post-deploy validation remain
required by the handoff. Production cutover remains a separate approval.

## Performance policy: existing v1 limits plus an unfrozen v2 p50 decision

`contracts/performance/profile-v1.json` already fixes p95 at at most 120% of the
Express baseline, zero unexpected outcomes, error increase at most 10/1000 and
login-success decrease at most 20/1000. It specifies ten flows, ten epochs,
20 warmups and 100 measured trials per flow/runtime/epoch, 20 requests/second,
5-second timeout and at most 16 in flight. The evaluator is not a load generator
and even a structurally passing result has `qualifyingEvidence=false` until its
submitted event claims are authenticated by a controlled launcher.

The reviewed READY plan additionally requires a pre-measurement p50 relative
cutoff, version-2 profile binding and three separately passing full runs. The v2
evaluator and schemas now exist; `profile-v2.template.json` intentionally has null
p50 and manifest inputs and cannot authorize measurement or PASS. No measured
result may be used to choose these thresholds. The active v1 profile remains
unchanged; completing evaluator code alone does not complete C01/C02/C03.

In contrast, `backup_restore/backup-restore-policy.json` still has null
`rpoSeconds`, `rtoSeconds`, and `maxArtifactRetentionSeconds`. These values need
an operational decision before a qualifying run, not adjustment after results.

## Observed execution-environment blockers

The following non-production diagnostics were run as the current unprivileged
user. They do not prove a root cause or rule out a separately configured runner.
No Docker endpoint was contacted and no host setting was modified.

| Diagnostic | Observed result |
| --- | --- |
| `unshare --user --map-root-user --net --pid --fork /usr/bin/true` | Exit 1: writing `/proc/self/uid_map` failed with `Operation not permitted` |
| `bwrap --unshare-all --ro-bind / / --die-with-parent /usr/bin/true` | Exit 1: loopback `RTM_NEWADDR` failed with `Operation not permitted` |
| `gh --version` | Installed GitHub CLI is 2.45.0 |
| `gh attestation --help` | `attestation` is not an available command |
| `command -v cosign` | No executable found on current PATH |

The two attempted unprivileged isolation routes cannot currently support the
required local collector. Do not fall back to the ambient production Docker
socket or change host security settings to bypass these failures. A designated
disposable VM/CI runner with the needed isolation capability is an alternative;
its identity and configuration have not been supplied in this session.

2026-09-10 user clarification: deployment is on this same server. Separate
test containers/stores/ports on this host are the intended development-test path,
not a requirement to obtain another physical server. Configuration-only checks
passed and candidate ports/resources were free. These facts do not authenticate
a controlled collector or authorize operating-service changes. The user requested
remaining implementation before real integration runs; no runtime was started.

## Trust bootstrap and project inputs

The [official Cosign installation guidance][cosign-install] describes an
artifact-key/TUF bootstrap followed by keyless bundle verification. A downloaded
release checksum or a source URL is not the cryptographic verification result.
The current host has no established, independently authenticated verifier chain.
An authenticated verifier and trust roots, plus retained verification evidence,
are required before executing scanner images. No researched candidate digest was
copied into the active lock.

The reviewed [toolchain decision](security/TOOLCHAIN_FREEZE_DECISION.md) selects
project-built candidates, but no tracked CI signing workflow, project registry
selection or trusted OIDC subject has been established. Local Git ownership does
not define a signing policy. Needed non-secret inputs are:

- Designated disposable runner/VM configuration and access mechanism.
- Project OCI repository and CI signing-policy configuration (or confirmation
  that a new setup is needed), plus the approved verifier/bootstrap trust source.
- RTO, RPO and artifact retention requirements.

Do not send or commit tokens, private keys or production `.env` files. Publishing
images, provisioning shared infrastructure or changing production settings must
not be silently inferred from a local qualification request.

[cosign-install]: https://docs.sigstore.dev/cosign/system_config/installation/
