# A01b/A02/A03 connected private-mail development

The canonical driver now exposes the approved
`email-verification-attach-handoff-exchange` and `password-reset-session-revoke`
IDs alongside the two existing password flows. The manifest lists those four
IDs explicitly and an asset regression checks the list against the executable
driver constants and approved order. All qualification/readiness flags remain false.

Private STARTTLS capture is consumed through an owned-runtime launcher; it is not
misrepresented as the existing `MAIL_PROVIDER=dev` mode. Runtime readiness checks
the actual accepted loopback connection and listener socket ownership before
requesting health. Session capability, PID/origin and CA digest bind the guarded
fixture subprocess to that development launch. This is not namespace containment,
authenticated binary identity or permission to attach to an existing service.

Verification covers expiry/replay, a distinct mandatory password-attachment target,
handoff/exchange, JWT signatures and exact session state. Session assertions run
before fixture teardown, so teardown cannot hide stale handoffs or no-op logout.
Reset establishes two known active refresh-token hashes, then requires exactly
those hashes revoked and no active sessions after reset. Mail tokens and token
hashes are private assertion inputs, not published result fields.

`test_mail_independent_roles.py` invokes separate hermetic role processes with real
HTTP, STARTTLS, RSA/HMAC and SQLite state transitions. It checks each flow in both
directions with exact per-trial role/path ordering. Wrong keys/signatures, wrong
refresh secrets in either direction, and attachment/ledger/state mutations must
fail. Success and failure paths check child PIDs, ports and private temporary files.
These are **test implementations, not the real Express/FastAPI engines** and not
live PostgreSQL/Redis evidence.

Independent code review of the complete mail source, role tests and asset mapping
is APPROVE with no findings. Independent architecture is CLEAR, so the combined
development-scope verdict is APPROVE. Startup rollback,
pre-/post-reap interruption, consumed pidfd reuse, capture/session cleanup and
malformed-ledger handling have hostile regression coverage. Cleanup exhaustion is a
typed failure, never a successful result hidden behind an earlier readiness error.
Leader verification on frozen mail/assets: 59 passed, 120 subtests (mail 31/7 and
assets/performance 28/113). Ruff/format passed for nine files and independent strict
mypy passed for six typed files. The concurrently edited Google launcher is excluded
from this approval; a full-suite result must be refreshed after its own freeze.

The v1 performance profile was rebound only to the new manifest bytes; numeric
policy, flow order and load parameters did not change. Existing bound measurement
plans/evidence are not rewritten and cannot be reused under the new hash. This is
not selection or freeze of the still-unset v2 p50 policy.

Remaining parent-task evidence includes actual Express/FastAPI execution on shared
disposable PostgreSQL/Redis, approved sample counts and authenticated G03 collection.
The overall replacement remains NOT_READY. Express production source, Prisma schema
ownership, the active toolchain lock and live service configuration are unchanged.
