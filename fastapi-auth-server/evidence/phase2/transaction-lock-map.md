# Phase 2 transaction and lock map

This map records repository-observed Express behavior and the current provisional
FastAPI proof boundary. It does not claim API parity, mixed-runtime safety, production
readiness, or replacement readiness.

## Status and retry policy

- `IMPLEMENTED + LIVE_PROVEN` applies only to a persistence store primitive exercised
  against the disposable Phase 2 PostgreSQL database. It does not mean that the
  corresponding FastAPI route or service exists.
- `NOT_IMPLEMENTED / DEFERRED` means that the end-to-end FastAPI flow and its proof are
  deferred to a later phase, even when a reusable model or Redis helper already exists.
- `NOT_RUN / DEFERRED` means that no Express/FastAPI shared-DB or shared-Redis
  interleaving test has run.
- Express interactive Prisma transactions in the flows below do not pass an explicit
  `isolationLevel`, retry limit, or backoff. The code therefore does not pin those
  properties per flow, and no repository-wide transaction retry wrapper was found.
- FastAPI `Database` pins `READ COMMITTED`. It retries only PostgreSQL SQLSTATE `40001`
  (serialization failure) and `40P01` (deadlock detected), with at most three total
  attempts. The default delays before attempts two and three are 25 ms and 50 ms.
  A non-retryable error or final failed attempt is re-raised; public API error mapping
  for retry exhaustion is not implemented.

## Flow map

| Flow | Express order, lock/isolation, and rowcount observed in source | FastAPI Phase 2 implementation and proof | Mixed-runtime status |
| --- | --- | --- | --- |
| Register/pending credential | `registerWithPassword` hashes first, reads User, then optionally reads PasswordCredential. A new account uses one nested `User.create` with PasswordCredential create; an existing verified user uses a separate PendingPasswordCredential upsert. There is no transaction spanning the reads and selected write, no explicit lock/isolation, and no rowcount check; uniqueness is left to database constraints/Prisma errors. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no Express create↔FastAPI create race. |
| Failed login/account lock | One Prisma transaction performs PasswordCredential atomic `increment`, returns only when the first `updateMany.count` is `0`, then conditionally updates `lockedUntil` when count is at least five. No explicit row lock/isolation is requested. The first result is not constrained to exactly one and the second rowcount is not inspected. | `IMPLEMENTED + LIVE_PROVEN` **for the store primitive only**. FastAPI enforces increment rowcount `0` or `1` and lock-update rowcount `0` or `1` in `READ COMMITTED`. Live 4-, 5-, and 20-request races produced exact final counts; the lock was absent below five and present at/above five. | `NOT_RUN / DEFERRED`: no 20-way Express/FastAPI shared-row race. |
| Token issue | One Prisma transaction locks exactly one ACTIVE User using `FOR UPDATE`, reads User+roles, prepares/signs the refresh JWT in memory, inserts one RefreshToken, then prepares the access JWT. The lock query requires one row; the insert relies on success/error rather than an explicit numeric rowcount. No explicit isolation/retry policy is passed. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no cross-runtime token issue/verification. |
| Refresh | JWT HS256 verification, audience extraction, hashing, and timestamp creation occur before the transaction. The transaction reads RefreshToken, locks the ACTIVE User with `FOR UPDATE`, conditionally revokes the old token with `updateMany.count === 1`, then signs and inserts the replacement token. No explicit isolation/retry policy is passed. | `IMPLEMENTED + LIVE_PROVEN` **for the DB rotation store primitive only**. FastAPI mirrors read → ACTIVE User `FOR UPDATE` → conditional revoke with rowcount exactly `1` → replacement insert in `READ COMMITTED`. A live 20-way race produced one success, one revoked old token, and one active replacement. JWT verification and the FastAPI refresh API are not implemented by this primitive. | `NOT_RUN / DEFERRED`: the live race was Python-only; no Express/FastAPI refresh or status-mutation interleave ran. |
| Logout | No DB transaction: RefreshToken `findFirst` for an active token, then `updateMany` revoke, then a separate audit write in the controller. The revoke rowcount is ignored; HTTP remains 204 and the returned audit user comes from the earlier read. No lock/isolation is requested. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no logout↔refresh schedule across runtimes. |
| Email verification request | User/PendingPasswordCredential read → EmailVerificationToken create → mail send → separate audit write. There is no encompassing transaction, lock, or rowcount check; a mail failure occurs after token persistence. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no cross-runtime request/confirm. |
| Email verification confirm/activate | Token is read before the transaction. Inside it: User read → PendingPasswordCredential read → conditional token-use `updateMany.count === 1`; activation then reads reservation/possible subject User, conditionally updates User with count `1`, and seeds/assigns roles. Password attachment instead creates PasswordCredential then deletes PendingPasswordCredential. No explicit row lock/isolation is requested. Audit and optional Redis handoff creation occur after commit. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no concurrent confirm or confirm→exchange interleave. |
| Password reset request | Active credential/User read → PasswordResetToken create → mail send → separate audit write. There is no encompassing transaction, lock, or rowcount check; a mail failure occurs after token persistence. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no cross-runtime request/confirm. |
| Password reset confirm | Password hash is prepared before the transaction. The transaction reads the usable token → conditionally marks it used with count `1` → locks User with `FOR UPDATE` → updates PasswordCredential → revokes all active RefreshTokens with `updateMany` and captures its count. Audit is separate after commit. No explicit isolation/retry policy is passed. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no concurrent confirm or refresh interleave. |
| OAuth identity resolve/create/link | SocialAccount is read before the transaction. The transaction may attach to a verified-email User, delete an unverified pending User, or read email/reservation state then create User+SocialAccount and upsert/assign roles. No explicit `FOR UPDATE` or isolation is requested. Role assignment uses `createMany(skipDuplicates)` without asserting its count; identity uniqueness is enforced by constraints/Prisma errors. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no provider-ID, verified-email, or reservation race across runtimes. |
| OAuth state/start | Redis `SET NX EX` creates the state with a 10-minute TTL, retrying random state generation at most three times. There is no DB transaction. | `NOT_IMPLEMENTED / DEFERRED` at the OAuth flow level. A generic Redis primitive does not constitute this flow. | `NOT_RUN / DEFERRED`: no Express start→FastAPI callback or reverse direction. |
| OAuth callback/identity/handoff creation | Redis Lua atomically `GET`+`DEL`s state first → provider token/profile calls → OAuth identity flow → separate audit write → Redis handoff `SET NX EX` with a 2-minute TTL and at most three code-generation attempts. These operations are not one transaction. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no callback→exchange cross-runtime path or handoff drain proof. |
| Password/email handoff creation | Password login or email confirmation finishes its DB/domain work, then the controller records audit, then Redis creates the handoff with `SET NX EX` and a 2-minute TTL. A handoff failure does not roll back the earlier DB/audit effects. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no cross-runtime producer/consumer path. |
| Handoff exchange/token issue | Redis `GET` reads raw serialized data → schema/binding/PKCE checks → raw-value CAS Lua consume. A valid consume happens before the separate token-issue DB transaction; audit is later and separate. Binding mismatch consumes zero; a valid race consumes once, but token-issue failure occurs after consumption. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no cross-runtime exchange race. |
| Admin status/role/revoke | Actor authentication/read is outside the mutation transaction. Status: User `updateMany` →, when required, User `FOR UPDATE` → RefreshToken `updateMany` → audit. Assign: Role upsert → UserRole `createMany(skipDuplicates)` → audit. Remove: Role read → UserRole `deleteMany` → User `FOR UPDATE` → token revoke → audit. Revoke: User `FOR UPDATE` → token revoke → audit. Status accepts exactly one changed row as true; assign requires count `1`; remove accepts count `>0`; revoke count is returned. No explicit isolation/retry policy is passed. | `NOT_IMPLEMENTED / DEFERRED` | `NOT_RUN / DEFERRED`: no same-target Express/FastAPI mutation. |
| Global rate limit | One Redis Lua command performs `INCR`, and sets/repairs TTL only when count is one or TTL is missing. The middleware compares the returned exact count with the request limit. There is no DB transaction. | `NOT_IMPLEMENTED / DEFERRED` at the middleware/API-flow level. A generic Redis increment helper does not constitute this flow. | `NOT_RUN / DEFERRED`: no combined Express/FastAPI key count or 429-boundary proof. |

## Source and evidence boundary

Express behavior above was read from:

- `auth-server/src/services/password-auth.service.ts`
- `auth-server/src/services/password-auth.store.ts`
- `auth-server/src/services/token.service.ts`
- `auth-server/src/services/email-verification.service.ts`
- `auth-server/src/services/email-verification.store.ts`
- `auth-server/src/services/password-reset.service.ts`
- `auth-server/src/services/password-reset.store.ts`
- `auth-server/src/services/user.service.ts`
- `auth-server/src/services/oauth-state.store.ts`
- `auth-server/src/services/oauth.service.ts`
- `auth-server/src/services/auth-handoff.store.ts`
- `auth-server/src/services/redis.client.ts`
- `auth-server/src/services/admin-user.service.ts`
- `auth-server/src/services/admin-user.store.ts`
- `auth-server/src/controllers/auth.controller.ts`
- `auth-server/src/controllers/oauth.controller.ts`
- `auth-server/src/middlewares/rateLimit.middleware.ts`

FastAPI primitive proof is limited to `persistence/database.py`,
`persistence/stores.py`, `infrastructure/redis.py`,
`tests/integration/test_postgres_phase2.py`, and
`tests/integration/test_redis_primitives.py`. The live outputs are in
`postgres-pytest.txt`, `postgres-junit.xml`, `redis-pytest.txt`, and
`redis-junit.xml`. Real backup restore, production-schema read-only smoke,
mixed-runtime interleaving, production refreeze, canonical worktree replay, canary,
cutover, and rollback proof remain deferred.
