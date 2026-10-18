# A04 test-only provider transport

`bin/provider_transport.py` and `adapters/provider_transport_preload.mjs` intercept
the fixed Google/Naver/Kakao token and user-info calls at the existing FastAPI
httpx and Express ky/fetch boundaries. Other endpoints/methods, redirects,
incorrect credentials, malformed or oversized inputs and timeout scenarios are
rejected without an external network fallback. This is application-level test
interception, not operating-system egress isolation or live provider validation.

The Python bootstrap wraps the real application lifespan to install and close
its test client. The Express side-effect-free transport library is separate from
`provider_transport_preload_entry.mjs`, which is the process preload entrypoint.
Private configuration requires owner match, exact0600, a regular file,
O_NOFOLLOW and bounded reads. The Node reader refuses growth beyond64KiB.
Tests invoke only the existing local Vitest executable; npm registry fallback is
not allowed. Child probes have bounded timeouts and module-relative paths.

Independent code/spec/security review: APPROVE. Architecture: WATCH.
Combined verdict: COMMENT. The downstream watch is that A05–A07 must provide a
launcher-owned private channel for subprocess token/user-info invocation records;
library-local call arrays alone cannot authenticate full server-flow provenance.

Fresh scoped checks:8 Python tests/7 subtests,11 Express Vitest tests from both
repository-root and auth-server working directories,37 existing FastAPI OAuth/
lifespan regressions, Ruff/format/strict mypy/strict TypeScript/Node syntax/diff checks.
The independent full contracts run passed156 tests/163 subtests at review time.

No production Express/FastAPI source, real provider credential, network provider,
registry, schema or operational owner changed. A05–A07 actual callback/link/handoff/
exchange consumers, mixed-runtime state proofs and live qualification remain open.

## Private child invocation channel continuation

`bin/private_provider_record.py` now supplies a launcher-owned anonymous pipe with
one-shot child binding, parent write-end handoff and destructive consumption after
child EOF. Actual Python and Node interceptors emit only schema/run/runtime/provider/
operation/sequence fields. URLs, credentials, codes, tokens and provider subjects
are excluded. Records are limited to 512 bytes each, 16 per stream and 8 KiB total;
the reader has an absolute deadline and refuses incomplete or mismatched streams.

Both writers require a nonblocking write descriptor. The Node writer checks Linux
fd-info flags with a bounded read instead of risking a blocking `writeSync` on a
caller-supplied FIFO. Channel initialization failures close both newly created
descriptors; malformed provider/operation types raise controlled errors. Tests
exercise real child-process output, cross-run/runtime bindings, replay, oversized
records, descriptor replacement, wrong-end/blocking pipes and initialization failure.

The scoped continuation has 14 tests/11 subtests and passing lint/format/strict
Python and TypeScript checks. Independent code re-review is APPROVE with no findings
and architecture is CLEAR; the combined bridge verdict is APPROVE. The architecture
review also repeated actual Node/Python child bridge checks 40 times. This closes the
earlier A04 invocation-channel WATCH, not the downstream A05 tasks.
A04-to-A05 launcher consumption and canonical registration are
being implemented separately; a matching snapshot marker is not pipe provenance.
This channel is a development observation boundary, not authenticated collector
attestation, verified runtime code identity or a qualification result.
