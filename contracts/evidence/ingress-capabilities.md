# Ingress capability evidence

## Decision

Repository evidence does **not** establish weighted routing, stable cohort routing, multi-step flow affinity, writer-path splitting, normalized cross-runtime metrics, or atomic rollback at the active public ingress. Production mixed-runtime canary is therefore **not approved** by this artifact.

The safe repository-evidenced topology is a single Express app endpoint behind an externally managed Cloudflare Tunnel/private HTTP path. Until the external ingress configuration is obtained and independently verified, migration must use synthetic validation followed by a **blue-green switch under a full writer maintenance outage**. Because path splitting is also unknown, the fallback must assume that all writer ingress is closed together rather than selectively routed.

## Repo-evidenced topology

| Capability/fact | Status | Repository evidence | Consequence |
| --- | --- | --- | --- |
| Public Auth Server name is `https://auth.financenow.kr` | Known | `auth-server/docs/HANDOFF_20260729.md:8`; `TEMIS_SSO_HANDOFF.md:524` | Public synthetic checks can target this hostname, subject to operator approval and non-mutating probes before cutover. |
| Current documented app endpoint is `http://192.168.0.4:4000` | Known, documentation snapshot | `auth-server/docs/HANDOFF_20260729.md:9` | A private upstream is documented, but the live upstream mapping is not checked into this repository. |
| Cloudflare Tunnel is managed on another server | Known | `auth-server/docs/HANDOFF_20260729.md:15` | The controlling ingress configuration and its routing features are outside this repository. |
| Cloudflare policy can distinguish `/admin/dashboard`; `/manage/dashboard` is the documented public alias | Known | `auth-server/docs/HANDOFF_20260729.md:15-21`; `auth-server/src/app.ts:76` | Some path policy exists, but this does not prove arbitrary path splitting, weighted routing, or writer-flow routing. |
| `/admin/*` and `/manage-api/*` mount the same router | Known | `auth-server/src/app.ts:82-83`; `auth-server/docs/HANDOFF_20260729.md:21` | Both aliases must be closed/fenced together. Closing only `/admin` leaves equivalent writer paths reachable through `/manage-api`. |
| Compose defines one `app` service and no load balancer/proxy service | Known | `auth-server/docker-compose.yml:1-19` | The checked-in deployment has no repository-local canary controller or second runtime upstream. |
| App HTTP publish defaults to host loopback and may be changed with `AUTH_HTTP_HOST` | Known | `auth-server/docker-compose.yml:18-19` | Default exposure is local-only; private-interface exposure is an operator choice, not an ingress feature. |
| A documented private-interface example exposes only HTTP as `192.168.0.4:4000` | Known | `auth-server/ops/DOCKER_INVENTORY.md:54-61` | PostgreSQL and Redis should remain loopback-only while the tunnel/private proxy reaches HTTP. |
| PostgreSQL and Redis Compose publishes are loopback-only | Known | `auth-server/docker-compose.yml:36-37,54-55`; `auth-server/ops/DOCKER_INVENTORY.md:44-61` | A second runtime on another host cannot share these stores using the checked-in defaults. A same-host or explicitly secured shared-state topology is required and must be separately evidenced. |
| `/healthz` is process liveness and `/readyz` checks PostgreSQL | Known | `auth-server/src/app.ts:54-65`; `auth-server/ops/README.md:85-94` | `/readyz` is the documented traffic-admission probe, but Redis readiness is not part of it. Synthetic validation must test Redis-backed flows separately. |
| Express trusts exactly one proxy hop | Known | `auth-server/src/app.ts:43` | Client IP correctness depends on the actual proxy chain matching this assumption. |
| Rate-limit identity is derived from Express `request.ip` | Known | `auth-server/src/middlewares/rateLimit.middleware.ts:16-18,26-28` | Canary comparison and abuse controls require verified trusted-proxy/client-IP behavior at the real ingress. |

## Required capabilities not proven by this repository

| Required capability | Status | Missing evidence / required proof |
| --- | --- | --- |
| Weighted routing between Express and FastAPI | Unknown / unsupported for planning | No Cloudflare Tunnel/load-balancer configuration, origin-pool definition, weight configuration, or controlled traffic-distribution result is checked in. |
| Stable cohort routing | Unknown / unsupported for planning | No deterministic user/header/cookie cohort rule or cohort persistence evidence exists. |
| Flow affinity across OAuth start → callback → handoff exchange | Unknown / unsupported for planning | No affinity cookie/header rule, callback pinning, or cross-request routing proof exists. Shared Redis makes cross-runtime consumption possible only after compatibility tests; it does not itself prove ingress affinity. |
| Flow affinity across password/email handoff and refresh/admin mutations | Unknown / unsupported for planning | No routing rule covers these multi-request/stateful flows. |
| Path split / independent close controls for root producers, OAuth callbacks, handoff exchange, and remaining writers | Unknown / unsupported for planning | The only path-policy fact is the documented Cloudflare behavior around the admin dashboard. There is no route-control API/config or rehearsal evidence for writer classes. |
| Atomic or immediately reversible upstream switch | Unknown / unsupported for planning | No declarative tunnel config, versioned change mechanism, propagation bound, or rollback rehearsal is present. |
| Normalized ingress metrics shared by both runtimes | Unknown / unsupported for planning | No checked-in ingress metric schema/dashboard identifies runtime, route template, status, latency, cohort, and request ID across both candidates. |
| Trusted client IP through the actual proxy chain | Unknown / blocking for rate-limit parity | The app uses `trust proxy = 1`, while Cloudflare Tunnel is documented on another server. The real hop count and sanitized forwarding-header policy are absent. |
| Shared production PostgreSQL and Redis/key namespace from both runtimes | Unknown / blocking for mixed canary | Compose exposes stores only on loopback and defines one app. No secured two-runtime network topology or credential test exists. |

Any one of weighted routing, stable cohort selection, or affinity being merely available in a vendor product is insufficient. Approval requires the **actual deployed configuration**, a deterministic test plan, observed routing results, rollback timing, and trusted-header proof for this service.

## Selected fallback: blue-green with full writer maintenance

The absence of proven weighted/cohort routing prohibits a production mixed-runtime canary. The absence of proven path-split controls means the transition must assume a complete writer outage from `STOP_ROOT_PRODUCERS` through `SWITCH_CLOSED`; if the ingress cannot close writer routes independently from read-only routes, close the entire application ingress.

Use [writer-surface-inventory.json](./writer-surface-inventory.json) as the authoritative repository-derived checklist. The required sequence is:

1. `STOP_BACKGROUND_OPS_WRITERS` — fence refresh/audit cleanup, admin grant, role backfill, identity merge, schema migration, Prisma Studio, provisioning, destructive Compose operations, and every externally discovered cron/systemd/CI/operator writer. Prove job in-flight `0`, process `0`, and lease `0`.
2. `STOP_ROOT_PRODUCERS` — close all OAuth starts, `/auth/login`, and `/auth/email-verification/confirm`; prove route in-flight `0` and record the last accepted OAuth-state/handoff-producing timestamp.
3. `DRAIN_OAUTH_CALLBACKS` — keep callbacks reachable for the OAuth-state maximum TTL. Code fixes this TTL at 600 seconds (`auth-server/src/services/oauth-state.store.ts:7-9`).
4. `STOP_OAUTH_CALLBACKS` — close all three provider callbacks, prove callback in-flight `0`, and record the last handoff creation timestamp.
5. `DRAIN_HANDOFF_EXCHANGE` — keep `/auth/exchange` reachable for the handoff maximum TTL. Code fixes this TTL at 120 seconds (`auth-server/src/services/auth-handoff.store.ts:7-8`).
6. `STOP_HANDOFF_EXCHANGE` — close exchange and prove its in-flight count is `0`.
7. `STOP_ALL_REMAINING_WRITER_INGRESS` — close all other `/auth` routes plus every `/admin` and `/manage-api` route, including conditional admin-denial audit and rate-limit audit paths. Prove writer-ingress in-flight `0` and record the last accepted writer timestamp.
8. `VERIFY_ALL_WRITERS_CLOSED` — inventory-by-inventory proof that ingress is closed, jobs are fenced, and writer ingress/job in-flight, process, and lease counts are all `0`. Any unclassified surface is a hard stop.
9. `WAIT_LIMITER_WINDOW` — wait the deployed `AUTH_RATE_LIMIT_WINDOW_SECONDS` after the last allowed `/auth` writer. The checked-in default/example is 60 seconds (`auth-server/src/config/env.ts:141`; `auth-server/.env.example:27`), but the deployed value must be captured rather than assumed.
10. `SWITCH_CLOSED` — change the single upstream while writer traffic remains closed. Record old/new origin identity, image digest, config version, change timestamp, and propagation observation.
11. `SYNTHETIC_VERIFY` — while public writer ingress remains closed, exercise health/readiness and an approved internal synthetic suite for password/email/OAuth/refresh/logout/admin/manage/audit behavior against the new origin and the shared state stores.
12. `REOPEN` — open FastAPI ingress and only the explicitly selected single-owner jobs. Confirm the inventory still reports zero unclassified/duplicate writers.

Rollback repeats the same writer close, state drain, zero-writer proof, limiter-window wait, closed upstream switch, and synthetic verification before reopening Express. An emergency rollback may skip graceful state preservation only with an explicit user-impact decision; it still closes all writers first and tells affected users to restart authentication flows.

## Evidence required to reconsider mixed-runtime canary

The decision may change only after all of the following are attached to this artifact or a successor:

1. Versioned Cloudflare/private-proxy configuration showing two origins, health checks, exact route matchers, weight/cohort rules, and rollback action.
2. A controlled distribution test proving requested weights and a stable cohort key without trusting client-supplied forwarding headers.
3. Multi-step routing evidence for OAuth, password handoff, email-verification handoff, refresh rotation, and admin mutations.
4. Verified proxy hop count and forwarding-header sanitization consistent with Express/FastAPI client-IP extraction and the shared global rate-limit namespace.
5. Common ingress metrics that identify runtime and normalized route while correlating a redacted request ID end to end.
6. Both runtimes reaching the same PostgreSQL and Redis/key namespace through an approved secured network, with producer/consumer and concurrency tests passing.
7. A rehearsed, timed rollback proving the upstream can be returned to the last Express image within the accepted bound.

Until then, capability status remains fail-closed: **synthetic + blue-green + full writer drain only**.
