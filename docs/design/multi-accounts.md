# Multi-account switching design

**Status:** implemented backend foundation; active-account claims gate behind operator flags and release into OIDC, the JWT payload, and SAML attributes.

## Goal and non-goals

Accounts (tenant-like workspaces) let one Better Auth user belong to several isolated units and switch the active one in a session. This design covers account definition, membership, and per-session switching in D1. Non-goals for this phase: portal UI, per-account branding, and delivering the active account as a claim in OIDC/SAML/WS-Federation tokens.

## Identity model

- **Identity source of truth is Better Auth.** `accounts` and `account_members` reference Better Auth user ids only; roles (`admin`, `user`) stay the platform-level roles managed by the Better Auth admin APIs. Account membership is a separate dimension and never grants platform administrator rights; administration of accounts is the `/api/admin` surface.
- **Accounts are first-party objects.** `accounts` holds an immutable UUID `id`, a unique `name` (1–128 characters from `[A-Za-z0-9_.-]`), an optional `description`, and audit metadata (`created_by`, timestamps). Names and descriptions are trimmed. Renaming is the same unique-constrained write (`account.update` audit event).
- **Membership is a plain association.** `account_members` holds `(account_id, user_id)` with a `role` constrained to `admin`/`member`, `granted_by`, and `granted_at`, plus an index on `user_id`. Creating an account atomically grants its creator the `admin` member role. Membership is verified by the store layer on every switch (the account join and the membership test are a single query).
- **The active account is per session, not per user.** `account_session_contexts` binds `(session_token, user_id, account_id, switched_at)` with `PRIMARY KEY (session_token)`, mirroring the `session_mfa_proofs` pattern: no Better Auth schema change, and two sessions of the same user may hold different account contexts. The member role is read through a join with `account_members` at claim time, so role updates take effect on the next token issuance without touching context rows. Removing a membership deletes the member's context rows for that account in the same D1 batch, so no session keeps an active account it no longer belongs to; the demotion and removal paths both refuse to strand an account without any `admin` member (409).
- **Retention:** the daily Worker Cron prunes context rows whose token cannot back a live session after the 31-day window (same convention as `cleanupSessionMfaProofs`).

## Administration API

All routes live under `/api/admin/accounts`, require an administrator session and the exact configured `Origin`, and are audited (`account.create`, `account.delete`, `account.member.add`, `account.member.remove`). Reading is session-gated but not audited, matching the existing admin read routes.

| Method and path | Behavior |
|---|---|
| `GET /api/admin/accounts` | Cursor list (`limit` 1–100, default 50), omits members. |
| `POST /api/admin/accounts` | `{name, description?}` → 201 with the account; the creator becomes its first `admin` member; 409 when the unique name exists; 400 on invalid input. |
| `PATCH /api/admin/accounts/{id}` | `{name?, description?}` → 200 with the updated account; 404 when absent; 409 when the unique name is taken. Audited (`account.update`). |
| `GET /api/admin/accounts/{id}` | Account detail with members (admin session). |
| `DELETE /api/admin/accounts/{id}` | 200 and removal of the account with its memberships, session contexts, and custom attributes in one D1 batch; 404 when absent. |
| `POST /api/admin/accounts/{id}/members` | `{userId, role?}` (default `member`) → 201; rejects unknown users (404), duplicate membership (409). Self-grants are allowed. |
| `POST /api/admin/accounts/{id}/invitations` | `{role?, ttlDays?, email?}` (default `member`, 7 days; 1–30 days) → 201 with ID and token. Optional email sends immediately; `delivered` reports success. Audited (`account.invitation.create`). |
| `GET /api/admin/accounts/{id}/invitations` | Up to 200 invitations, with IDs, masked token prefixes and `pending`, `expired`, `accepted` or `revoked` status. |
| `DELETE /api/admin/accounts/{id}/invitations/by-id/{invitationId}` | 200 `{revoked:true}`; 404 for absent/wrong-account ID; 409 for accepted or revoked. Expired invitations can be revoked. |
| `POST /api/admin/accounts/{id}/invitations/by-id/{invitationId}/reissue` | `{deliverTo?}` or empty body atomically revokes the old invitation and creates a new one with the same role, recipient metadata and original duration. Returns a new ID and token; optional delivery reports `delivered`. 404 if absent; 409 if accepted/revoked. |
| `DELETE /api/admin/accounts/{id}/invitations/{token}` | 200 revocation of a pending invitation; 404 when absent or already consumed. Audited (`account.invitation.revoke`). |
| `POST /api/admin/accounts/{id}/invitations/{token}/deliver` | `{to}` emails the invitation through the deployment's Resend credentials or — for headless local testing — points at the built-in mock mailbox `/dev/mocks/invitation-email` (only with the `ENABLE_DEV_MOCKS` flag; it records messages for retrieval and must never be enabled in production, since bodies carry invitation tokens). Records `deliverTo`/`deliveredAt` on the invitation row; 503 without a configured channel, 409 expired, 502 failed send. Audited (`account.invitation.email`). |
| `PATCH /api/admin/accounts/{id}/members/{userId}` | `{role}` → 200; 404 when the membership is absent; 409 when demoting the last `admin` member. Audited (`account.member.role.update`). |
| `DELETE /api/admin/accounts/{id}/members/{userId}` | 200; 404 when the membership is absent; 409 when removing the last `admin` member. Also drops the removed member's session contexts for the account. |

The new ID cannot redeem an invitation. The token is returned on issuance only, not by the list, and there is no delivery-by-ID endpoint: to send a listed invitation, reissue it. If sending fails after issuance, the response still returns the token with `delivered: false`; the old token remains revoked. If mail is not configured the request fails with 503 before issuance. The legacy token-keyed delivery and deletion endpoints remain supported. **Existing implementation stores invitation tokens in plaintext in D1**, and the legacy token-keyed endpoints include the token in their request path; protect database and request/audit logs accordingly. Token hashing and removing token-bearing legacy paths require a separate migration.

- **Per-account authorization.** An app-access policy can additionally require membership in one account (`requiredAccount`): the gate is a membership requirement evaluated before the group gate, it respects the enforcement mode (observe passes through with an observed outcome), and a temporal access request never bypasses it. In the admin surface it is `{requiredAccount}` on the policy (null = platform-wide).

## User-facing switching API

| Method and path | Behavior |
|---|---|
| `GET /api/accounts` | Session-gated. Every membership of the acting user with its account object and role; `active` flags the session's own account and `activeAccountId` repeats it (null before the first switch). |
| `POST /api/accounts/switch` | `{accountId}` binds the account to the calling session. Same-origin only (exact `AUTH_BASE_URL` origin), audited (`account.switched`). 403 when the user is not a member — a nonexistent account and a non-membership are indistinguishable, so no account existence oracle leaks over the user surface. |
| `POST /api/accounts/join` | `{token}` redeems an account invitation: same-origin only, audited (`account.joined`). The token is single-use — the consumed-flag write and the membership insert are one D1 batch, and an already-member user aborts before any write so the token is never burned. Invalid, expired, revoked, replayed and already-member invitations all resolve to one identical 403 so no invitation state leaks to non-members. Roles beyond the invitation's fixed `member`/`admin` grant require the admin surface. |

## Token claim release (active-account claims)

The active account is released into protocol tokens only when the operator sets `ENABLE_ACCOUNT_CLAIMS=true`; without the flag the surfaces fail closed and behave byte-identically to the pre-claim build.

The optional **attribute allowlist** on a claim release policy narrows the *keys* of the released user attribute set per subject: an empty list releases nothing to that application, a listed subset releases only those keys (unknown keys release nothing), and `null` (the default) releases the full flag-permitted set. It is enforced on both the JSON claim path (OIDC/JWT) and the SAML/WS-Fed attribute URN path, after the kind gate.

- **Surfaces.** OIDC access tokens and ID tokens (and UserInfo) through the oauthProvider `claimReleaseExtension` claim contributors, which resolve the account via the `sid`-backed session id for session-backed grants; the JWT plugin's payload through `definePayload`; and SAML 2.0 (`/saml/sso`) and WS-Federation (`/wsfed/signin`) assertions as attributes at their issuance points (resolved through the session token and session id).
- **Shape.** One structured, URI-namespaced claim `<IdP origin>/claims/active-account` with `{id, name, role}` on the OIDC/JWT surfaces; SAML 2.0 and WS-Federation carry `<origin>/claims/active-account-id`, `-name`, `-role` as simple string attribute URNs. The `role` is the member role inside that account (`admin`/`member`), never the platform role.
- **Fail-safe semantics.** The global operator flags make release possible at all; a per-application claim release policy (`/api/admin/claim-release-policies/{subject}`, an AND with the flags) narrows which kinds one application receives, and a row can only narrow, never widen. A session that never switched releases no claim, so single-account deployments change nothing; removing a membership drops the session context row, so no token issued later can carry a non-membered account; unknown or session-less grants (client-credentials, deleted sessions) release nothing.
- **Schema migration.** `account_session_contexts` gains a nullable `session_id` column (in-place `ALTER` for deployed databases, with an index) because the OIDC path only carries the session id (`sid` = Better Auth session id), while the switch surface keys on the raw session token.

## What remains open

- (None in code scope; the mock mailbox must be disabled in production deployments — it is fail-closed behind `ENABLE_DEV_MOCKS`.)
