# External (time-limited) accounts

For people outside the company, such as contract hardware developers, who sign in to
agent-hub and, when needed, to one GitLab project. An external account cannot hold
employee service roles and stops working at the end of its term.

## Rules

- Account type `EXTERNAL`; `User.accountExpiresAt` holds the term end (naive UTC).
- The term is set in whole days, 1–365. It ends at 23:59:59.999 KST on the last day.
  The admin screen offers 3 months (90 days), 6 months (180 days) or a custom day count.
- Extending adds days to the remaining term (or to today if already expired); the result
  cannot be more than 365 days ahead. An expired account works again once extended.
- The only role an external account may hold is `gitlab:user`. `agent-hub:user`, `sso:*`
  and every other employee role are refused. The type cannot be changed to or from
  `EXTERNAL` through the user-type controls.

## Lifecycle

1. An SSO administrator opens `/oauth2/admin/dashboard` → "외부 계정" and enters email,
   name, term and whether GitLab is needed.
2. SSO issues a one-time setup link (valid 72 hours, stored only as a hash). The admin
   either copies the link and sends it directly, or chooses mail delivery.
3. The guest sets a password on the link page; the account becomes `EXTERNAL`/ACTIVE with
   the chosen term. Guests sign in with email and password only.
4. Extend, suspend and reactivate from the same screen; each requires a reason.

Audit events: `external_invitation_created|resent|cancelled|accepted|delivery_failed`,
`external_account_extended` (previous and new term), `admin_user_status_changed`
(suspend/reactivate) and `external_account_expired` (system).

## Enforcement

Every sign-in path rejects an expired account at request time: OIDC authorize, token
exchange, UserInfo and central-session sign-in (`OIDC_ACCOUNT_EXPIRED`), and the legacy
password, social, refresh and `/auth/me` paths (treated as suspended).

`python -m wiseacct_sso.ops.expire_external_accounts` (needs `DATABASE_URL`) then revokes
refresh tokens and central SSO sessions of newly expired accounts and records
`external_account_expired` once per term. It is idempotent; run it every 10 minutes.
An OIDC access token already issued can live at most its 5-minute lifetime, and UserInfo
rejects it immediately.

## Claims for relying services

| Claim | Value |
| --- | --- |
| `account_type` | `employee`, `customer` or `external`; absent when unclassified |
| `account_expires_at` | Unix seconds, external accounts only; updated after an extension at the next sign-in or UserInfo call |

## Client policy

| client | allowedUserTypes | requiredRoles | allowWithoutRequiredRole |
| --- | --- | --- | --- |
| `agent-hub-dash` | EMPLOYEE, CUSTOMER, EXTERNAL | `agent-hub:user` | true |
| `gitlab-temis` | EMPLOYEE, EXTERNAL | `gitlab:user` | false |

While a client has no `allowedUserTypes`, it accepts every type, so external accounts are
already admitted wherever the role rule lets them in.

## GitLab: one project only

GitLab CE gives every regular user read access to `internal` projects. Mark each guest as
**External** in GitLab so they see only projects they are members of:

1. The guest signs in to GitLab via SSO once (needs `gitlab:user`). The account is created
   blocked (`omniauth_block_auto_created_users`).
2. A GitLab admin approves it and ticks **Admin → Users → Edit → External**.
3. Add the guest to the one project as Developer.

When the SSO term ends, GitLab sign-in fails, but the GitLab membership remains; remove it
when agent-hub flags the guest as ended.
