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

## Image route compatibility research (not activation)

Read-only upstream inspection used Cosign v3.1.3 source commit
`11926fa5bbbbde47e88fc006b625a17769b743b2` as a compatibility candidate, not an
approved release or trust pin. Its layout writer tags an image-index root as
`kind=imageIndex`, whereas local bundle discovery searches the image-root route.
This source-level mismatch means the requested multiarch local-image success
contract remains unproven; no authenticated binary was run to resolve it.
See [layout writing](https://github.com/sigstore/cosign/blob/11926fa5bbbbde47e88fc006b625a17769b743b2/pkg/oci/layout/write.go)
and [local verification](https://github.com/sigstore/cosign/blob/11926fa5bbbbde47e88fc006b625a17769b743b2/pkg/cosign/verify.go).

A possible alternate route requires a separate reviewed implementation, not an
unconditional `verify-blob` substitution. The OCI layout root `index.json` is a
navigation wrapper, **not** the registry image-index bytes. The candidate artifact
would be the exact `blobs/sha256/<locked-index-digest>` bytes, independently checked
against the locked digest/size. Wrapper/referrer/bundle-layer descriptors and the
target index-to-platform-manifest-to-config/layer graph still need independent
integrity and selection checks. See [layout index resolution](https://github.com/sigstore/cosign/blob/11926fa5bbbbde47e88fc006b625a17769b743b2/pkg/oci/layout/index.go).

Generic DSSE artifact verification accepts a matching subject digest and is not an
image-signature semantic filter. An alternate consumer claiming the v3 image-signing
contract must reject message-signature bundles and unrelated attestations, require
one subject with only the locked SHA-256 digest, and require predicate type
`https://sigstore.dev/cosign/sign/v1` with an empty predicate. These constraints come
from the [image-signing statement constructor](https://github.com/sigstore/cosign/blob/11926fa5bbbbde47e88fc006b625a17769b743b2/cmd/cosign/cli/sign/sign.go)
and are stricter than [generic artifact verification](https://github.com/sigstore/sigstore-go/blob/55aa6240784677449a564e66a0fca7a6a3605ecd/pkg/verify/signature.go).
They do not replace exact certificate identity/issuer, trusted-root, transparency,
or cryptographic checks.

Directory descriptors and mode-0700/0400 files do not seal an entire OCI layout
against same-UID mutation. Actual image execution still needs the approved isolated
backend and immutable child-facing material. The current image refusal and UNFROZEN
lock therefore remain necessary; this research closes no qualification gate.
