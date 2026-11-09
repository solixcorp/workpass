# Account Lockdown

**Model:** authentik's Account Lockdown feature
(<https://docs.goauthentik.io/security/account-lockdown/>, Enterprise; 2026.5+), adapted to this
Worker + D1 stack. Implemented backend; no portal UI.

## What it does

Lockdown is the emergency response for suspected compromise: one audited action that takes an
account fully out of service.

| Authentik action | This implementation |
|---|---|
| Deactivates the user | `banned = 1` (Better Auth sign-in gating; OPAQUE and token-exchange gates already deny banned accounts) |
| Sets an unusable password | Credential password replaced with a hash of a random secret nobody holds; the OPAQUE credential record (the password-less equivalent) is deleted |
| Terminates all active sessions | All Better Auth sessions deleted; offline OAuth refresh/access tokens revoked by the installed D1 ban triggers in the same statement |
| Revokes all tokens | OAuth access/refresh tokens revoked via the ban triggers; trusted devices revoked |
| Creates an audit event | `identity.user.lockdown` with acting user and target; the reason is recorded in `account_lockdowns` |

Deliberately **kept**: passkeys and TOTP/HOTP enrollments. Re-verifying a factor during recovery
is evidence the original owner is back (authentik likewise advises re-enrolling rather than wiping).
Downstream application sessions cannot be revoked by the IdP and must not be claimed otherwise.

Protected accounts: lockdown refuses unknown users with 404; admins can lock any local account,
including other admins (the reason and actor are recorded).

## API

All require a cookie session; admin routes enforce the platform admin role and exact-origin
mutating requests (`requireAdministrator`). Routes live under `/api/security`:

| Endpoint | Who | Notes |
|---|---|---|
| `POST /api/security/account-lockdown` | self-service | Body `{ reason }` (1–500 chars). Destroys the acting session as part of the action; the response is final. |
| `POST /api/security/account-lockdown/user/{userId}` | admin | Body `{ reason }`. Returns per-action counts. |
| `POST /api/security/account-lockdown/user/{userId}/unlock` | admin | Body `{ new_password? }` (8–128 chars). Clears the ban; see recovery below. |
| `GET /api/security/account-lockdown/user/{userId}` | admin | History, including reasons. |
| `GET /api/security/account-lockdown/self` | any session | The caller's own history. |

## Recovery (administrator action)

1. `POST …/unlock` — clears `banned` (and the ban reason), marks the lockdown row lifted
   (`lifted_at`, `lifted_by`), optionally sets a new credential password.
2. If no password was supplied, set one through Better Auth
   `POST /api/auth/admin/set-user-password`; until then the account has an unusable password.
3. Sessions, tokens, and trusted devices stay revoked — they are not restored by the unlock.
   The user signs in fresh and re-enrolls trusted devices; passkeys and TOTP still work.
4. The unlock is audited as `identity.user.lockdown_lifted`.

## Design notes

- The destructive side effects run in one D1 batch, each guarded by an SQL
  `EXISTS (… banned = 1)` condition, so a concurrent ban or race with ban expiry can never
  half-apply. The ban update fires the OIDC offboarding triggers that revoke tokens atomically.
- A ban through another path (Better Auth `ban-user`, SCIM deactivate) while a lockdown row is
  already open returns `409 already_locked` instead of duplicating history.
- Change counts in the batch may aggregate trigger-modified rows on some SQLite runtimes;
  the code treats the ban statement's `changes >= 1` as success for that reason.

Related: `src/security/account-lockdown.ts` (actions), `src/security/lockdown-routes.ts`
(routes), `account_lockdowns` table in `src/db/schema.ts`.
