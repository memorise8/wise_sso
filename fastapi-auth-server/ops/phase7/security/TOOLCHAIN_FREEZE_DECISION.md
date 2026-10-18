# Phase 7 toolchain freeze decision

Decision date: 2026-09-06. Baseline reviewed:
`5e1695aa31a6930075e17142c00d20f63a0ca5fd`.

Decision: **BLOCKED for activation**. Keep the active lock `UNFROZEN` and
replacement verdict `NOT_READY`. This is a candidate selection record, not
collected security evidence, a completed signature verification, or permission to
publish images. No row currently qualifies for `FREEZE`.

The reviewed active lock SHA-256 is
`1f49556d623ef350906de4b114cbd565e93aa4c1773ba2e504255ad4ed1a7376`.
Unknown values below are literal `null`; a source workflow or a documented image
tag is not proof of the artifact served by a registry.

## Candidate decisions

`REBUILD` selects a project-built candidate route, still blocked on reviewed
source inputs, build recipes, registry ownership, and signing identity. It does
not mean a build occurred. `BLOCKED` keeps the upstream candidate under review.
Source references linked below are research evidence, not selected build inputs.
All selected source commits and release versions remain `null`.

| Lock role | Route | Candidate source / distribution evidence | Selected repository / version / source commit | Verdict | License and maintenance review |
| --- | --- | --- | --- | --- | --- |
| builder | Project-built | Local exact-image build contract in `../build-exact-image.sh`; builder implementation not selected | `null` / `null` / `null` | REBUILD | Review builder, base image and all build utilities; no builder dependency selected |
| collector | Project-built | Local `online_stager.py` and `offline_stager_intake.py`; controlled execution implementation outstanding | `null` / `null` / `null` | REBUILD | Review project code, base image and verifier dependencies; project owns maintenance |
| gitleaks | Project-built | [Gitleaks release workflow][gitleaks] | `null` / `null` / `null` | REBUILD | MIT upstream; reviewed release, base SBOM and updates required |
| npm-audit | Project-built | [npm audit command][npm]; scanner is an npm CLI command | `null` / `null` / `null` | REBUILD | Review exact npm/Node release licenses and complete runtime SBOM |
| pip-audit | Project-built | [PyPI publication workflow][pip-audit]; release-file provenance is not OCI provenance | `null` / `null` / `null` | REBUILD | Apache-2.0 upstream; review pinned Python dependencies and base SBOM |
| ruff | Upstream candidate | `ghcr.io/astral-sh/ruff`; [OCI build and attestation workflow][ruff] | `null` / `null` / `null` | BLOCKED | MIT upstream; chosen image and both architectures still need verification |
| semgrep | Project-built | [Official Docker usage][semgrep] | `null` / `null` / `null` | REBUILD | LGPL engine requires exact manual review under local policy; rules/other components require separate review; rebuilding does not waive licensing |
| trivy | Upstream candidate | [Incident advisory and verification guidance][trivy] | `null` / `null` / `null` | BLOCKED | Review selected release against incident history, license and base SBOM; a documented known-safe release is not a verified local pin |
| vulnerability-db | Upstream candidate | `ghcr.io/aquasecurity/trivy-db`; [DB configuration][db] | `null` / `null` / `null` | BLOCKED | Review database sources and redistribution terms; enforce collection freshness |
| java-db | Upstream candidate | `ghcr.io/aquasecurity/trivy-java-db`; [DB configuration][db] | `null` / `null` / `null` | BLOCKED | Review database sources and redistribution terms; enforce collection freshness |
| checks-bundle | Upstream candidate | `ghcr.io/aquasecurity/trivy-checks`; [DB configuration][db] | `null` / `null` / `null` | BLOCKED | Review selected rules and redistribution terms; version and payload binding required |

## Digest and identity evidence

For image rows, `platform` and `config` list values in the order
`linux/amd64`, `linux/arm64/v8`. Artifact rows have no platform/config pin in the
lock schema; their separate payload hash is required instead. `n/a` is only a
table annotation and must never be copied into the lock. The bundle requirement
below is a future acceptance requirement, not an assertion that a bundle exists.

| Role | Index / artifact manifest digest | Platform digests | Config digests | Payload SHA-256 | Expected issuer / exact subject | Required evidence |
| --- | --- | --- | --- | --- | --- | --- |
| builder | `null` | `null`, `null` | `null`, `null` | n/a | `null` / `null` | Verified signature + provenance + Rekor bundle |
| collector | `null` | `null`, `null` | `null`, `null` | n/a | `null` / `null` | Verified signature + provenance + Rekor bundle |
| gitleaks | `null` | `null`, `null` | `null`, `null` | n/a | `null` / `null` | Verified signature + provenance + Rekor bundle |
| npm-audit | `null` | `null`, `null` | `null`, `null` | n/a | `null` / `null` | Verified signature + provenance + Rekor bundle |
| pip-audit | `null` | `null`, `null` | `null`, `null` | n/a | `null` / `null` | Verified signature + provenance + Rekor bundle |
| ruff | `null` | `null`, `null` | `null`, `null` | n/a | `null` / `null` | Verified signature + provenance + Rekor bundle |
| semgrep | `null` | `null`, `null` | `null`, `null` | n/a | `null` / `null` | Verified signature + provenance + Rekor bundle |
| trivy | `null` | `null`, `null` | `null`, `null` | n/a | `null` / `null` | Verified signature + provenance + Rekor bundle |
| vulnerability-db | `null` | n/a | n/a | `null` | `null` / `null` | Verified signature + provenance + Rekor bundle |
| java-db | `null` | n/a | n/a | `null` | `null` / `null` | Verified signature + provenance + Rekor bundle |
| checks-bundle | `null` | n/a | n/a | `null` | `null` / `null` | Verified signature + provenance + Rekor bundle |

Ruff's published workflow supplies a useful provenance lead. An attestation is
not automatically the image signature required by the existing intake. Retain
and independently verify both required artifact roles before selecting pins.

The Trivy advisory describes a GitHub Actions issuer and an Aqua-wide identity
regexp. That regexp is not an exact signer subject and cannot be copied into this
lock or extended to DB/checks artifacts. The reviewed public evidence did not
establish the three DB/checks signing identities. This is an evidence gap, not a
claim that those artifacts can never have signatures. Re-signing opaque upstream
bytes would establish project custody, not cure missing upstream provenance.

Project-built candidates need a documented owner, exact registry repository,
reviewed source/build workflow commit, chosen issuer and exact certificate
subject, and independent verification of the resulting signed subjects. Do not
derive the project identity from a local Git remote or invent an OIDC subject.
An observed certificate alone must not define the trusted identity policy.

## Additional blockers and implementation order

1. Bootstrap trust remains unresolved. The current lock requires
   `/usr/bin/docker` plus its hash, but that does not authenticate the daemon or
   the signature verifier. Record the verifier version, binary provenance/hash,
   trust roots and verification policy before executing downloaded artifacts.
2. Select and verify the candidate input versions. Local development pins
   (`pip-audit==2.10.1`, `ruff==0.16.4`) are compatibility inputs only, not
   authenticated scanner image selections. Capture index bytes, each selected
   platform manifest and config, their computed hashes, signatures, provenance,
   verification output/hash and observation time. Verify the full digest chain.
3. Establish DB/checks provenance and freshness. The existing security gate
   requires database evidence no older than 24 hours. A digest selection record
   cannot substitute for fresh collection, or authorize silently replacing a
   previously reviewed payload.
4. Define advisory origins and actual network destinations. Both advisory
   origins remain `null` and the active allowlist stays empty. The current
   `online_stager.validate_lock` accepts exactly registry hosts plus advisory
   origins. Registry authentication/CDN and verification-service destinations
   may require a separately reviewed contract change after observed evidence;
   do not add wildcard destinations or bypass the projection check.
5. Implement the controlled daemon/verifier boundary with negative tests before
   activation. `online_stager.run` currently rejects even a schema-valid
   `FROZEN` lock, and `security_gate.validate_control_attachments` requires the
   exact empty `UNFROZEN` contract. Changing the JSON alone cannot enable
   collection. Keep these refusals until the replacement path verifies isolated
   daemon ownership, default-deny egress, artifact authenticity before execution,
   cleanup, sanitization and atomic receipts.
6. Independently review all candidate evidence and the consumer changes. Only a
   separate reviewed activation change may fill the active lock, after all 11
   subjects, bootstrap, origins and destination policy are complete. A partially
   populated frozen lock must continue to fail. Even a frozen lock is not a
   security PASS or replacement approval.

The next local implementation slice can define and test the private-daemon and
verifier contracts while retaining check-only execution. Publishing/signing
images requires the project's registry and identity configuration; no production
credentials, services or routing are part of that work.

## Evidence scope and review

This record uses official sources inspected in the preceding session review and
the local baseline named above. No registry digest resolution, Cosign execution,
image build, signing, network-policy qualification or scanner run was performed
for this decision. External documentation URLs are research references, not
immutable collected evidence. Workflow URLs below are pinned to inspected source
commits and are not selected release commits.

Independent review: approved on 2026-09-06 by the separate read-only
`freeze_decision_review` agent, with no blocking findings. Review checked complete
11-role coverage, unknown pins, license caveats, the active lock hash, local
consumer behavior, freshness and activation sequencing. Approval covers only this
blocked decision and the next local development scope. It does not approve
toolchain activation, artifact execution, image publication/signing, or Express
replacement. External artifact authenticity remains unverified.

[gitleaks]: https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/.github/workflows/release.yml
[npm]: https://docs.npmjs.com/cli/v11/commands/npm-audit/
[pip-audit]: https://github.com/pypa/pip-audit/blob/089ac0ede7cb99beb41e59c018124552307597b7/.github/workflows/release.yml
[ruff]: https://github.com/astral-sh/ruff/blob/a5ef1f43fcf70b3edb4e3fdffbae71af85c5e42e/.github/workflows/build-docker.yml
[semgrep]: https://semgrep.dev/docs/semgrep-ci/sample-ci-configs
[trivy]: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
[db]: https://trivy.dev/latest/docs/guide/configuration/db/
