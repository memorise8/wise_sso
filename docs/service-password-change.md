# Service password change

`POST /oauth2/service/password-change` lets a trusted service (the dot-office hub) change a
user's SSO password on that user's behalf. The hub relays the password the user typed as their
current one and the new one; the SSO checks both and replaces the hash.

## Authentication

Same mechanism as `POST /oauth2/service/external-invitations`: a short-lived bearer token from
the `client_credentials` grant at `POST /oauth2/token`, but with its own scope,
**`password-change`**.

- The service client in `SERVICE_CLIENTS_JSON` must list the scope, for example
  `{"clientId": "agent-hub-service", "clientSecretHash": "...", "scopes": ["external-invite", "password-change"]}`.
  Removing it from the configuration stops existing tokens at once.
- The token must carry the scope: request `scope=password-change` (or both scopes separated by a
  space), or omit `scope` to receive every scope the client has. An `external-invite`-only
  token gets `403 insufficient_scope`.
- The per-client limit of 30 calls a minute shared by all service endpoints applies.

## Request

```http
POST /oauth2/service/password-change
Authorization: Bearer <service token>
Content-Type: application/json

{"email": "member@example.com", "current_password": "...", "new_password": "..."}
```

Strict JSON: exactly these three string fields, no query string, body at most 8 KiB, each
password 1–1024 characters. The email is trimmed and lower-cased.

## Responses

`204 No Content` on success. Every reply carries `cache-control: no-store`.

Errors use the same envelope as the invitation endpoint:

```json
{"error": {"code": "invalid_current_password", "message": "The current password is not correct"}}
```

| Status | `error.code`               | Meaning |
|--------|----------------------------|---------|
| 400    | `invalid_current_password` | Wrong current password, unknown email, or an account that is suspended, deleted, awaiting email verification, past its term (external) or locked after failed logins. The cases are not told apart. |
| 409    | `no_password`              | Active account without an SSO password (Google/social sign-in only). |
| 400    | `weak_password`            | The new password fails the password-reset policy (`PASSWORD_MIN_LENGTH`, counted in UTF-16 code units). |
| 400    | `same_password`            | The new password equals the current one. |
| 429    | `rate_limited`             | Too many failed attempts for this email (5 within 15 minutes). |
| 400    | `INVALID_REQUEST`          | Malformed body, wrong content type or a query string. |
| 401    | `invalid_token`            | Missing, unknown or expired service token (`www-authenticate: Bearer ... scope="password-change"`). |
| 403    | `insufficient_scope`       | The token or the client lacks `password-change`. |
| 429    | `RATE_LIMITED`             | The service client exceeded its per-minute call limit. |

The current password is checked first, so `weak_password` and `same_password` are only
reported to a caller who knows it.

## Behaviour

- Verification uses the same Argon2 hasher as the login page; unknown addresses still pay for a
  hash check so they cannot be told apart by timing.
- A wrong current password on an active, unlocked account counts toward the login lockout
  (5 failures lock sign-in for 15 minutes), exactly like a failed login.
- Throttling: failed attempts are counted per email in Redis (`wise:svc:pwchange:fail:<sha256
  of the email>`, 15-minute window). Unknown addresses are counted too, so the limit does not
  reveal whether an account exists. At 5 failures every request for that email answers
  `rate_limited` until the window ends, even with the right password.
- Success does what password-reset confirm does: new hash, failed-login count and lock cleared,
  `passwordUpdatedAt` set, `User.ssoSessionVersion` incremented (every SSO session ends) and
  every unrevoked refresh token revoked. The user signs in again everywhere, including the hub.
- If the password changes concurrently between the check and the write, the request answers
  `invalid_current_password` and nothing is written.
- Every outcome writes an `AuditLog` row with `eventType` `service_password_change`, `outcome`
  `success` or `failure`, `userId`/`targetUserId` when the account is known, `reasonCode`
  (`INVALID_CURRENT_PASSWORD`, `NO_PASSWORD`, `WEAK_PASSWORD`, `SAME_PASSWORD`,
  `RATE_LIMITED`) and `detailsJson` `{"clientId": ...}`. Passwords are never logged or stored
  anywhere but as the new hash.
