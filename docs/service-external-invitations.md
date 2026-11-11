# Service-issued external invitations

agent-hub invites an outside developer with one call; the person gets one mail, sets a
password, and lands back on the hub. Rules are the same as the admin portal's external
account panel (whole days 1–365, only `gitlab:user` as a service role).

## Calling it

1. Token (client_secret_post or Basic):

   ```
   POST /oauth2/token
   grant_type=client_credentials&scope=external-invite&client_id=agent-hub-service&client_secret=…
   → {"access_token", "token_type": "Bearer", "expires_in": 300, "scope": "external-invite"}
   ```

   Opaque, kept hashed in Redis for 5 minutes; no refresh token. 30 calls/minute per client
   (token requests included).

2. Invitation:

   ```
   POST /oauth2/service/external-invitations
   Authorization: Bearer <token>
   {"email", "days", "gitlab", "return_to", "invited_by", "note"?}
   → {"status", "invitation_id"?, "expires_at"?, "account_type"?, "account_status"?}
   ```

| status | when | what SSO does |
|---|---|---|
| `invited` | no account yet | creates an external invitation (or reuses the pending one: new token, newer `return_to`, longer term, roles merged) and mails the sign-up link |
| `exists_external` | external account exists | term becomes max(current, now + days); adds `gitlab:user` if asked; mails a notice with `return_to`. A suspended account stays suspended (`account_status`). |
| `exists_employee` | any other account, or a pending employee invitation | nothing |

`expires_at` is the account term (end of the KST day, ISO UTC with `Z`). After sign-up the page
moves to `return_to` (JSON for the fetch-based page, 303 for a plain form post), but only while
`return_to` still starts with a configured prefix.

Errors: `{"error": {"code", "message"}}` — `INVALID_REQUEST` / `INVALID_RETURN_TO` 400,
`invalid_token` 401, `insufficient_scope` 403, `RATE_LIMITED` 429,
`INVITATION_DELIVERY_FAILED` / `NOTICE_DELIVERY_FAILED` 503 (the change is kept; calling again
is safe and re-sends).

Audit: `service_external_invitation_created|resent`, `service_external_account_extended`,
`service_external_skipped`, `service_external_notice_failed`, each with `clientId`,
`invitedBy`, `returnTo`, `days`, `gitlab`, `note`.

## Configuration

- `SERVICE_CLIENTS_JSON` — `[{"clientId": "agent-hub-service", "clientSecretHash": "<argon2id>", "scopes": ["external-invite"]}]`.
  Client IDs must not overlap OIDC or legacy clients; requires `OIDC_ENABLED=true`.
- `SERVICE_INVITE_RETURN_TO_PREFIXES` — comma-separated https URLs ending in `/`
  (default `https://dash.temis.me/invite/`).
- Migration `20261111000000_invitation_return_to` adds `EmployeeInvitation.returnTo`.
