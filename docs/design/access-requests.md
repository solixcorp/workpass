# Access requests (just-in-time application access) design

**Status:** backend implementation of the access-request authority. Browser UI is a follow-up
backend-client surface; API and audit events are the product surface here (matching the SWA
direction). The model benchmarks authentik's access requests but is simplified to this
platform's structures — there is no flow engine, so the request flow is a required
justification prompt.

## Purpose

Users request access to an application when they need it instead of an administrator
provisioning `app_access_policies` group membership in advance. Requests are routed to
configured reviewers; approval grants **time-limited** access that expires automatically
without cleanup, supporting just-in-time and least-privilege access. Every lifecycle step is
recorded in the tamper-evident audit stream.

## Model (benchmarking authentik's terminology)

| authentik | This system |
|---|---|
| Application (requestable) | Protocol-qualified policy subject: `saml:<entityId>`, `oidc:<clientId>`, `wsfed:<realm>`, `swa:<origin>` — the same subject space as `app_access_policies`, so one grant surface covers all federated apps |
| Request rule | `request_rules` + bound reviewers (users, groups) |
| Request rule binding | `request_rule_bindings`: one rule per application subject, plus pending-expiry and max-granted-expiry constraints and the requester eligibility set (empty set = every authenticated user, per the application-access convention) |
| Request flow | Simplified: an always-collected justification field (1–2000 chars). No MFA re-auth stage; the app's existing `require_mfa` policy still applies at issuance |
| Reviewer | User or directory-group members bound to the rule; the requester can never review their own request |
| Expiry | Approved access = a temporal grant row with `expires_at`; reads evaluate activity lazily, so no scheduler is required for revocation |

## Security design

- **No standing-privilege escalation.** An approved request does not modify
  `app_access_policies` or directory groups. It inserts one row into
  `app_temporal_grants` (subject, user, request, granted window, approver). The policy
  engine consults the active grant only after the group gate has already failed, so
  configured access continues to work unchanged and a grant can never widen a policy
  beyond "the group gate passes for this user".
- **`require_mfa` is not bypassed.** The temporal grant bypasses only the group gate;
  second-factor requirements and method constraints continue to gate at issuance time.
- **Time-bounded by construction.** `max_granted_expiry_seconds` on the binding caps every
  grant; the requester may ask for less but never more. Pending requests themselves lapse
  after `pending_expiry_seconds` (status `lapsed`); the scheduled cleanup finalizes lapsed
  rows, and reads also treat inactive grants as inactive without waiting for the scheduler.
- **Reviewer integrity.** Minimum-approver counting uses an `access_request_approvals`
  table with one row per (request, reviewer); a deny by any matched reviewer denies the
  request outright; self-review is refused structurally; the approval writes the grant
  only after the minimum is reached.
- **One request at a time.** A partial unique index allows at most one `pending` request
  per (user, subject).
- **Audit.** `access_request.created / approved / denied / cancelled / revoked / lapsed`
  events via the shared `auditStandaloneOperation` authority (actor = requester/reviewer,
  target = subject), inheriting the tamper-evident hash chain.
- **Notifications are best-effort, never authoritative.** When
  `ACCESS_REQUEST_WEBHOOK_URL` is set, creation and decisions POST a JSON summary. There
  are no retry queues: reviewers must also be able to discover pending work from the
  reviewer queue API. Notification modes: `all` (every matched reviewer summarized) or
  `random` (a subset of size `min_reviewers`, sampled with a crypto shuffle).

## Data model

- `request_rules` — name (1–64 `[A-Za-z0-9_.-]`), `min_reviewers` (1–5),
  `notify_mode` (`all` | `random`), created_by/at.
- `request_rule_reviewers` / `request_rule_reviewer_groups` — reviewer bindings;
  `request_rule_reviewer_groups` references `directory_groups` (deletion cascades).
- `request_rule_bindings` — unique per subject, `rule_id`, `pending_expiry_seconds`
  (60 s–90 d), `max_granted_expiry_seconds` (1 h–30 d), created_by/at.
- `request_binding_requesters` / `request_binding_requester_groups` — requester
  eligibility bindings; an empty set is open to every user.
- `access_requests` — subject, user, binding, justification, status
  (`pending → approved | denied | cancelled | lapsed`, then approved rows may become
  `revoked`), `requested_expiry_seconds`, `granted_expires_at`, `pending_expires_at`,
  decided_by/at, decision_note.
- `access_request_approvals` — (request, reviewer) decisions with notes.
- `app_temporal_grants` — one row per approved request; `revoked_at` for early revocation.

## API surface

Administrator (`/api/admin/...`, `requireAdministrator`): CRUD for rules and bindings
(with reviewer/requester binding inline), listing all access requests, and revoking an
active grant.

User (`/api/access-requests/...`, session-authenticated, same-origin check on mutation):
`requestable` (Discover list), `POST` create, `me` (My Requests), `/:id/cancel`,
`reviews` (For My Review queue), `/:id/review` (approve/deny with note).

The policy engine change is internal: `evaluateAppAccess` now resolves an active temporal
grant (subject + user, not revoked, not expired) as a pass before reporting a group-gate
denial. All five federated issuance surfaces (OIDC consent, SAML, WS-Fed, SWA, consent
page) inherit this automatically.

## What is deliberately out of scope

- Authentik's full flow engine (stages, policies on flows, MFA re-auth elevation). The
  justification prompt replaces it; elevation hardening is a separate reviewed design.
- Per-group minimum reviewers (`min_reviewers is per-group`); the minimum is a total.
  The `min_reviewers` column leaves room for the extension.
- Browser UI (Discover page / reviewer queue). The API contract above is the surface a
  client builds on; the project's documented direction defers client work.
- Notification transports beyond the single webhook URL (email/Slack routing is a
  follow-up transport decision).
