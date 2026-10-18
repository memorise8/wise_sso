# Cloudflare Access OIDC extension

Implementation authorized by the user on 2026-10-15 following review of the Agent Hub
handoff and `cloudflare-access-oidc-draft-20261015.md`. This is a separate FastAPI-only
feature, not an expansion or waiver of the frozen Express migration qualification.

## Boundaries

- Feature branch: `feat/fastapi-oidc-cloudflare-access`, initially based on `1e4fea6`.
- Existing `/auth/*`, `/users/*`, `/admin/*`, static assets, JWKS and discovery retain
  their contracts. Express does not implement the new `/oauth2/*` endpoints.
- Off by default. OIDC has independent clients, Redis keys, error envelopes and tokens.
- Existing Prisma schema remains authoritative. No SQL migration or automatic DDL.
- No production data, credentials, routing, provider-console or Cloudflare changes.
- Integrate against the reviewed canonical FastAPI baseline before release; this feature
  must not silently become a prerequisite for completing the existing migration.

## Protocol contract

Authorization Code flow only: `GET /oauth2/authorize`, `POST /oauth2/token`, and
`GET /oauth2/userinfo`. The token endpoint accepts bounded form bodies and either
`client_secret_basic` or `client_secret_post`, never both. Redirects match registered
strings exactly. `openid` is required; `email profile` are allowed. S256 is the only
PKCE method and is required for the Cloudflare client. Supplied state and nonce are
preserved. Invalid clients/redirects never cause external redirects.

OIDC-only `/oauth2/login` and `/oauth2/providers/{provider}/start|callback` connect
password and existing social identities without modifying old login assets/callbacks.
No automatic signup, identity linking or role assignment occurs in this flow.
Short-lived browser-bound transactions use CSRF protection, not persistent SSO sessions.

Code TTL is 60 seconds; transaction TTL is 10 minutes; ID and UserInfo tokens live
5 minutes. Code keys and opaque bearer keys use digests in `wiseacct:oidc:*`.
Authenticated code owners consume once before redirect/PKCE validation; an owner
binding error burns the code. Unauthenticated or other-client requests cannot burn it.
Legacy handoff codes and tokens are not valid OIDC credentials, or vice versa.

ID tokens use the existing RS256 key/kid and issuer, with audience equal to the OIDC
client ID. Claims include sub, email, email_verified, optional name, iat, exp, optional
nonce, and groups. Groups are sorted unique `serviceKey:name` strings restricted by
the client's service allowlist. Legacy role-object token claims remain unchanged.

ACTIVE status, verified email, and any configured required role are checked before
code issuance, again at exchange, and at UserInfo. There is no `agent-hub:user`
auto-grant. Existing administrator role APIs remain the sole grant mechanism.

Issuance prepares Redis state before committing successful audit and returning raw
credentials. Audit failure prevents successful delivery; prepared state is removed
or expires. Consumed codes cannot retry after failure. No distributed atomic commit
is claimed. Secret/code/token/verifier/state/nonce values must not appear in logs.

## Runtime configuration (do not enable in production without deployment approval)

| Setting | Meaning |
| --- | --- |
| `OIDC_ENABLED` | Defaults to `false`; enabled startup requires clients and public origin |
| `OIDC_PUBLIC_ORIGIN` | Exact HTTPS origin, without trailing slash; used for POST Origin checks |
| `OIDC_CLIENTS_JSON` | Separate array of confidential OIDC client policies; defaults to `[]` |
| `OIDC_GOOGLE_REDIRECT_URI` | Optional exact `${OIDC_PUBLIC_ORIGIN}/oauth2/providers/google/callback` |
| `OIDC_NAVER_REDIRECT_URI` | Optional corresponding Naver callback |
| `OIDC_KAKAO_REDIRECT_URI` | Optional corresponding Kakao callback |

Each client requires `clientId`, `redirectUris`, `clientSecretHash` (Argon2id PHC),
`requiredRoles` (nonempty OR), and `groupsServiceKeys`. `requirePkce` defaults to true;
`allowedScopes` defaults to `openid`, `email`, `profile`. Client IDs cannot overlap
legacy client IDs or audiences. Callback queries cannot predefine code/state/error
response fields. Existing callback query bytes otherwise remain unchanged.

Only explicitly configured OIDC provider callbacks appear on the new login screen;
the corresponding existing provider credentials must already be configured. No old
provider callback URI is replaced. Client-secret generation and private delivery are
deployment tasks; no real secret was generated or recorded during implementation.

New IP limits are 60 requests/minute per bounded endpoint bucket; token client limits
are 20/minute, before Argon verification. They use independent digest-keyed OIDC Redis
namespaces. Existing authentication rate-limit buckets are not changed.

The new login document alone adds registered callback origins to CSP `form-action`,
so browsers can follow its POST-to-303 callback navigation. Existing page policies
remain unchanged; no wildcard or request-derived origin is added. Exact callback
validation still occurs on the server.

## Verification and rollout gates

Local verification covers both client authentication methods, exact redirects, PKCE,
nonce/signature/audience, role revocation, single-use concurrency, cross-protocol
rejection, CSRF/browser binding, isolated provider callbacks, audit/store faults and
legacy contracts with the feature disabled and enabled. Mock/in-memory evidence must
be distinguished from real PostgreSQL/Redis and provider/Cloudflare evidence.

After canonical FastAPI migration and a separately approved feature deployment:

1. Register the new social callbacks without replacing existing callback addresses.
2. Configure Cloudflare Auth/Token/Certificate URLs explicitly; discovery is unchanged.
3. Use a separate test Access application, isolated from the PIN policy. Verify actual
   allow/deny behavior with `groups=agent-hub:user`, not only the dashboard test button.
4. Observe nonce, PKCE and client-authentication method without recording credentials.
5. Record global/application/policy session durations and effective maximum continued
   access after role removal. Five-minute ID tokens do **not** imply five-minute Access
   sessions. Verify Cloudflare session revocation separately.
6. Only after approval change the dash application and retire PIN. A rollback to Express
   removes OIDC; preserve an explicitly reviewed fallback, never an unrestricted bypass.

No local implementation/test result alone changes the migration's `NOT_READY` status
or authorizes a production deployment.

## Reproducing local validation

From `fastapi-auth-server`, use the pinned environment from `uv.lock`:

```sh
uv run --frozen pytest -q
uv run --frozen ruff check src tests
uv run --frozen mypy src tests
./ops/run-oidc-integration.sh
```

The legacy Express body-parser oracle also needs the existing locked `auth-server`
Node dependencies. In this worktree the prior worktree's installed dependencies were
reused read-only through `NODE_PATH` and `PATH`, with npm offline mode enabled.

The opt-in live runner requires locally available `postgres:17-alpine` and
`redis:7-alpine` images, Docker, and `.venv/bin/python`. It creates new labeled tmpfs
containers, random loopback ports, a synthetic test database and Redis DB 15; applies
only checked-in Prisma migrations; runs the actual Uvicorn app; then removes only its
own containers. It does not reuse preview or production stores. The live scenario
covers both client authentication methods, signatures/claims, six-way single-use code
exchange, role recheck with row locking, UserInfo revocation, audit hygiene and zero
legacy refresh sessions. This is development integration evidence, not Cloudflare,
real social-provider, production ingress or formal migration qualification evidence.

## Development verification checkpoint — 2026-10-15

- Full FastAPI suite: **1,487 passed, 119 skipped**. Skips are opt-in integration or
  environment-specific probes, not passes. One existing TestClient deprecation warning.
- OIDC-focused suite: **91 passed**.
- Separate real PostgreSQL/Redis/Uvicorn run: **1 passed**; newly created containers
  removed and the run-label inventory verified empty.
- Ruff, formatter check, strict mypy: passed across all **133** source/test Python files.
  `bash -n` and `git diff --check` passed.
- Independent security/code review: **APPROVE for this development branch**, no open
  reported findings; not an approval for production or canonical integration.
- Real browser CSP smoke: Chrome **144.0.7559.132**, installed Playwright **1.61.1**.
  Ephemeral loopback auth and self-signed HTTPS callback fixtures used the actual
  `oidc_form_action_sources()` and `SecurityHeadersMiddleware`. A same-origin form
  POST followed by 303 reached the registered HTTPS callback; an unregistered origin
  was blocked by Chrome `form-action` and received **zero** callback requests. Temporary
  servers, certificates and browser fixtures were removed. This verifies navigation
  policy, not the real Cloudflare account, production ingress, or social providers.

Remaining release work: canonical FastAPI integration/revalidation, approved real
provider callback registration, real Cloudflare allow/deny and session-revoke tests,
and separately approved deployment/PIN transition. Feature remains disabled by default.

## References

- [Cloudflare generic OIDC](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/generic-oidc/)
- [OIDC Core](https://openid.net/specs/openid-connect-core-1_0-18.html)
- [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749.html)
- [PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)
- [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html)
