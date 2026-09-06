# B02 dormant blob consumer — no authenticated toolchain activation

`fastapi-auth-server/ops/phase7/security/controlled_executor.py` now connects
standard-bundle admission and local blob hashing to a bounded Cosign-shaped
subprocess invocation. Bundle and artifact bytes are copied into sealed memory
files and those exact descriptors are validated and consumed alongside the sealed
verifier/trust-root descriptors. Source mutation cannot substitute child-facing
bytes. Borrowed descriptor-number reuse cannot close an unrelated replacement inode.

The development runner reuses B01's unreaped-leader/pidfd process-group drain.
Pipe EOF does not reap the leader before group signaling; a successful parent
cannot leave a same-group child alive merely by closing inherited output pipes.
Startup, selector and ownership-handoff failures have cleanup regressions.
This is not namespace isolation or containment of descendants that escape the group.

The dormant blob command follows the [official Cosign verification contract](https://docs.sigstore.dev/cosign/verifying/verify/).
Success uses process exit status, not a parsed `Verified OK` string or a caller-authored
JSON verification receipt. Bounded stdout/stderr are represented by hash and size
only. Local tests run an explicitly synthetic fixture executable that emulates the
CLI; **no downloaded Cosign release was authenticated or executed**.

The public qualification entrypoint still refuses before descriptor access or
process creation. A caller-supplied FROZEN/verified flag cannot activate it.
Image verification is explicitly refused until local-layout and index/platform/config
digest projection are implemented. The active toolchain lock remains unchanged and
UNFROZEN; no signer, issuer, verifier digest or root digest was selected by this change.

Independent code review: scoped APPROVE. Independent architecture: B02 CLEAR.
Validation:42 controlled-executor tests;75 including B01; Phase7 static review and
Ruff/format/strict mypy passed; fork/closed-pipe regression repeated10 times.

Parent B02 remains incomplete. B01 live containment, B03 independent bootstrap
authentication and activation, image projection, actual signed-artifact validation,
collector provenance and all downstream qualification consumers remain required.
Development observations and fixture process exits must never become READY evidence.
