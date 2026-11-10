# Internal Auth Backend API v1 (Draft)

**Status:** implementation contract draft. Browser/UI screens are out of scope. The OAuth authorize and consent paths are protocol endpoints required for relying parties, not a frontend deliverable.

## Conventions

- Base URL: `https://<configured-idp-host>`.
- JSON request/response bodies unless noted. All routes are served by the Cloudflare Worker.
- Authentication sessions use `HttpOnly`, `Secure` (on HTTPS), `SameSite` cookies issued by Better Auth. Do not expose the session token in frontend storage.
- Rate limiting, trusted origins, HTTPS, and Cloudflare deployment secrets are required before production; current code uses a local configuration-first PoC.
- Better Auth rate limits are configured to persist in D1, with stricter limits for password and passkey verification endpoints. Review the thresholds and D1 write cost before rollout.
- Errors use a non-sensitive JSON message/code. Never return password hashes, secret material, or raw internal errors.
- Public self-service account creation is disabled. A short-lived bootstrap registration route is only available when the deployment explicitly enables it and supplies a separate bearer token.

## Health

### `GET /`

Returns service status and pointers to the external API contract and OIDC discovery document. Does not expose identity data or secrets.

### `GET /health`

Unauthenticated process/runtime liveness only; does not expose D1 state, credentials, or tenant data.

```json
{ "status": "ok", "runtime": "cloudflare-workers" }
```

## Local operator setup (no UI)

1. Copy `.dev.vars.example` to the ignored `.dev.vars` and replace the auth secret and migration token with independent random values.
2. Temporarily set `ENABLE_MIGRATIONS=true` in `.dev.vars`, start `bun run dev:local`, and call `POST /_internal/migrate` with `Authorization: Bearer <MIGRATION_TOKEN>`.
2a. Local verification smokes (disposable databases only): `bun run scripts/passkey-smoke.ts --migrate-token <t> --admin-token <t>` drives both passkey verification ceremonies headlessly, and `bun run scripts/directory-smoke.ts --migrate-token <t> --admin-token <t>` exercises the directory group API including authorization and audit checks.
3. Temporarily set `ENABLE_ADMIN_BOOTSTRAP=true` and a random `ADMIN_BOOTSTRAP_TOKEN` of at least 32 bytes; call `POST /api/admin/bootstrap` with that bearer token to create the first admin account. The endpoint works only while the user table is empty and assigns the admin role.
4. Turn both feature flags off, remove both temporary tokens from `.dev.vars`, restart the Worker, and sign in through the normal API before calling admin APIs.

Never commit `.dev.vars`, production secrets, migration tokens, or bootstrap tokens. This is an operator bootstrap procedure, not an employee self-registration flow.

## Password and username authentication

### `POST /api/auth/sign-in/email`

Better Auth email/password login. JSON body: `email`, `password`, optional `rememberMe`, `callbackURL`. Success issues the session cookie. Use this for email login.

### `POST /api/auth/sign-in/username`

Username/password login. JSON body: `username`, `password`, optional `rememberMe`, `callbackURL`. Success issues the same session cookie.

### `POST /api/auth/sign-out`

Invalidates the current IdP session and clears the session cookie.

### `POST /api/auth/sign-up/email`

Always returns `404` and writes a denied-registration audit event. It is not available for bootstrap; use the separately gated `POST /api/admin/bootstrap` route.

### `POST /api/admin/bootstrap` (bootstrap only)

Disabled by default. To create the first administrator in a controlled environment, operators must temporarily set `ENABLE_ADMIN_BOOTSTRAP=true` and a random `ADMIN_BOOTSTRAP_TOKEN` of at least 32 bytes, then send `Authorization: Bearer <token>`. Body: `email`, `name`, `username`, `password`. The endpoint refuses to run after the first user exists, creates the user with the admin role, and writes an audit event. Disable the flag and remove the token immediately afterward. Regular employee creation uses the authenticated Better Auth admin API.

## Passkeys

Passkey endpoints are implemented by Better Auth and require an authenticated session for registration. Browser clients must invoke WebAuthn APIs and pass their resulting ceremony responses; the Worker owns challenge generation, origin/RP-ID checks, challenge consumption, credential verification, and persistence.

- `GET /api/auth/passkey/generate-register-options` — create credential options; requires a fresh session.
- `POST /api/auth/passkey/verify-registration` — verify and store a credential; requires the same ceremony cookie/session.
- `GET /api/auth/passkey/generate-authenticate-options` — create assertion options.
- `POST /api/auth/passkey/verify-authentication` — verify an assertion and issue an IdP session.
- `GET /api/auth/passkey/list-user-passkeys` — list current user's credentials.
- `POST /api/auth/passkey/delete-passkey` and `POST /api/auth/passkey/update-passkey` — manage current user's credentials.

Registration and authentication must use the exact HTTPS origin configured by `AUTH_BASE_URL` and its hostname as the WebAuthn RP ID. Production RP ID/origin changes require an intentional migration plan.

## OPAQUE login (RFC 9807) (implemented)

Password-free login over OPAQUE (RFC 9807) with the plaintext password never reaching the Worker. Server material and credential records are sealed with AEAD (`OPAQUE_MASTER_KEY`; cipher selected by `SEALED_STORAGE_CIPHER`, default xchacha20poly1305, FIPS-aligned aes256gcm optional).

- `POST /api/opaque/register/start` — session-authenticated; body `{registrationRequest}`. The credential identity derives from the acting session's own email (never from the request body); returns `registrationResponse`, `credentialIdentifier`, `serverIdentity`.
- `POST /api/opaque/register/finish` — session-authenticated; body `{record}` (sealed credential); returns `{registered: true}`.
- `POST /api/opaque/auth/start` — public, rate-limited; body `{user}`. Opens a single-use login transcript with a strict expiry.
- `POST /api/opaque/auth/finish` — verifies the transcript and creates the session. The login runs the shared gate (banned accounts, device risk); a `step_up` risk decision issues the session with `stepUpChallenge: { required: true, methods, expiresAt }` in the response body and SSO issuance stays withheld until a second factor is verified (accounts with no enrollable factor fail closed), matching the password/passkey pipeline.

## OIDC / OAuth 2.0

- `GET /.well-known/openid-configuration` — OpenID Provider configuration.
- `GET /.well-known/oauth-authorization-server/api/auth` — RFC 8414 metadata.
- `GET /.well-known/webfinger?resource=acct%3A<user>%40<email-domain>` — optional issuer discovery. It is disabled unless `OIDC_EMAIL_DOMAIN` is configured and only returns an issuer link for `acct:` resources on that exact domain. The Worker must also be reachable on the email domain over HTTPS for Tailscale discovery; the route and live Tailscale login have not been validated in a deployed tenant.
- `GET /api/auth/jwks` — public signing keys; no private key material is returned.
- `GET|POST /api/auth/oauth2/authorize` — authorization endpoint; authorization code with exact registered redirect URI and PKCE should be the relying-party default.
- `POST /api/auth/oauth2/token` — token endpoint.
- `GET /api/auth/oauth2/userinfo` — claims for a valid access token.
- `POST /api/auth/oauth2/revoke` — revoke a token/refresh token where supported.
- `POST /api/auth/oauth2/introspect` — token state where supported.
- `POST /api/auth/oauth2/consent` — complete user consent after the user is authenticated.
- `POST /api/auth/oauth2/register` — disabled by default. When temporarily enabled, it requires the separate `CLIENT_REGISTRATION_TOKEN` as a bearer token (at least 32 bytes); it is rate-limited and clients are required to use PKCE. Keep this token out of relying-party/browser traffic and turn the feature flag off after provisioning.
- Back-channel logout targets are denied by default after the OIDC guard migration. An operator with database access must explicitly approve the exact HTTPS URI in `oidc_logout_uri_approvals` before client registration or update. Check the endpoint owner and DNS and restrict database access; URI approval is not a network egress firewall and does not prevent DNS rebinding or an approved host changing ownership. Use network-level egress controls where available. If existing clients already have back-channel URIs, the migration intentionally fails until operators inventory them, create `oidc_logout_uri_approvals` and add explicitly reviewed URIs. The Better Auth built-in dispatcher rejects redirects but does not resolve DNS when validating a URI.
- Better Auth 1.7.18 back-channel delivery failures are emitted as structured Workers Logs events named `oidc.backchannel_logout.failure`, with client ID where available and a sanitized reason. Configure log retention and alerts separately. These logs are not a durable delivery journal, do not record success, and do not retry failed deliveries. The log parser depends on the pinned provider's message format and must be revalidated on upgrade.
- `POST /api/auth/token` — disabled to avoid exposing a second, unrelated JWT token-issuance path.

The authorize flow redirects unauthenticated users to `/sign-in` and users needing consent to `/consent`. These are relying-party/browser return locations, not routes implemented by this Worker; a separate client is required before interactive OIDC can complete. No frontend is included. Confirm the selected OIDC profile, PKCE behavior, logout semantics, claims mapping, and real test-RP interoperability before production.

## User lifecycle and session revocation

The Better Auth admin plugin supplies authenticated/authorized account-management operations under `/api/auth/admin/*`, including create/list/update users, ban/unban, and user/session revocation. The first administrator is created by the gated bootstrap route with the `admin` role; no administrator ID is hard-coded in Worker configuration. Create an employee with `POST /api/auth/admin/create-user` (`email`, `name`, `password`, and `data: { username }`); only the application retains the initial password, while the API stores its password hash. This plugin route returns HTTP 200 on successful creation.

- Disable an employee with `POST /api/auth/admin/ban-user` (`userId`, optional `banReason`): Better Auth blocks new sign-ins and deletes the user's IdP sessions as part of the ban operation. Verify the behavior and D1 failure semantics in the deployed environment.
- After the reviewed `/_internal/migrate` migration installs the OIDC offboarding database guards, setting `banned` revokes the user's stored OAuth access and refresh tokens, including `offline_access`, and clears cached refresh-rotation responses in the same database statement. Guards also reject persisted user-token inserts while the account is banned. Existing banned users' stored tokens are revoked when the migration runs. Unbanning does not restore revoked tokens. These guards do not revoke self-contained JWTs already issued or ensure downstream application logout; in-flight JWT issuance and deployed D1 concurrency still require verification. Do not claim this protection before the migration has succeeded on the target database.
- Re-enable only through `POST /api/auth/admin/unban-user` after authorization.
- Revoke all IdP sessions with `POST /api/auth/admin/revoke-user-sessions` (`userId`).
- Password changes and role changes use the Admin plugin's corresponding management endpoints; role changes are limited by Better Auth permissions.
- Removal is distinct from suspension and should require an approved retention/deprovisioning policy.

IdP session revocation does not guarantee immediate termination of an application-local session or already-issued self-contained access token. Each relying party must be checked for token/session lifetime, back-channel logout/introspection support, and its own revocation propagation. The five-minute offboarding objective is not yet verified.

## Security audit events

### `GET /api/admin/audit-events`

Admin-only query endpoint. Supports optional `actorUserId`, `targetUserId`, `eventType`, `outcome=started|success|failure`, ISO-8601 `from`, `to`, `limit` (1–100; default 50), and an opaque `cursor` (the last event ID returned). Timestamps require a time and explicit timezone (for example `2026-11-09T00:00:00Z`); invalid timestamps, an invalid limit, or a `from` later than `to` return 400. Results contain event ID/time, actor/target IDs, event type, outcome, and route path only. Never include request body, password, token, cookie, assertion, or secret. Pagination is ordered by timestamp and event ID descending; `nextCursor` is null when there is no additional row.

### `GET /api/admin/audit-events/verify`

Walks the positioned audit log and recomputes every entry hash, reporting contiguity and content-hash verification plus the count of legacy (pre-tamper-evidence) entries. Administrator session required. Detection only: D1 is not immutable, and retained entries are not deleted before one year.

### `GET /api/admin/audit-events/{eventId}`

Admin-only lookup for a single audit event, including an event ID returned after an audit finalization failure. Returns `{ "event": { ... } }` or 404; the list and detail responses use `Cache-Control: no-store`.

Audit events are written to D1. The Worker writes a `started` event before invoking each tracked operation, then updates that record to `success` or `failure` only if it is still present and unfinalized. If the initial audit insert fails, the operation returns `503`. If finalization fails or the started record is missing or already finalized, the auth response is withheld with `503` where the operation handler supports it; the returned event ID supports operational reconciliation. A failed update can leave an event `started`, but a missing event cannot be recovered from that row. This still cannot undo an operation already committed in D1, so reconciliation is required for incomplete events.

If account suspension, removal, or password change succeeds but trusted-device revocation fails, the response is `503` with the audit event ID and the event remains `started`; the account mutation may already have happened and operators must reconcile the trusted-device state before retrying.

## Fingerprint device-risk policy (implemented; disabled by default)

The integration now supports Fingerprint Server API event lookups for password/username and passkey sign-ins when explicitly enabled. It uses a risk input only; it never replaces password/passkey authentication or makes a device permanently trusted. Login bodies may include `fingerprint: { event_id }`. Sealed Client Results are not implemented and are rejected rather than silently ignored. The default mode is `disabled`; observe/enforce behavior is described below and in [Device risk and trusted-device policy](../security/device-risk-and-trust.md).

Configuration: set `FINGERPRINT_MODE=observe|enforce`, `FINGERPRINT_REGION=us|eu|ap`, and the Worker secret `FINGERPRINT_SERVER_API_KEY`. Optional controls are `FINGERPRINT_MIN_CONFIDENCE` (default `0.7`), `FINGERPRINT_SUSPECT_SCORE_THRESHOLD` (unset unless deliberately selected), `FINGERPRINT_MAX_EVENT_AGE_SECONDS` (default `120`), and `FINGERPRINT_ALLOWED_ORIGINS` (comma-separated additional event origins). Login-history GeoIP checks follow authentik's GeoIP policy semantics: `GEOIP_CHECK_HISTORY_DISTANCE` (default `false`), `GEOIP_HISTORY_MAX_DISTANCE_KM` (default `100`), `GEOIP_DISTANCE_TOLERANCE_KM` (default `50`), `GEOIP_HISTORY_LOGIN_COUNT` (default `5`), `GEOIP_CHECK_IMPOSSIBLE_TRAVEL` (default `true`; the built-in allowance is 1,000 km per elapsed hour), and `GEOIP_IMPOSSIBLE_TOLERANCE_KM` (default `100`). Session binding variables are `SESSION_BINDING_MODE` (default `disabled`), `SESSION_BINDING_NETWORK` (default `off`), and `SESSION_BINDING_GEOIP` (default `off`), and the step-up challenge window `STEP_UP_CHALLENGE_TTL_SECONDS` (default `900`). Do not configure production thresholds without a false-positive review in observe mode.

- `GET /api/security/trusted-devices` — list the current user's trusted devices, including revoked/expired state.
- `POST /api/security/trusted-devices` — enroll a device. Requires `event_id`, current `password`, and optional `label`; the event must be fresh, verified, unused, and sufficiently confident. Device trust expires after 30 days.
- `DELETE /api/security/trusted-devices` — revoke all current user's devices; requires current password confirmation.
- `DELETE /api/security/trusted-devices/{deviceId}` — revoke one of the current user's devices; requires current password confirmation.
- `DELETE /api/security/trusted-devices/user/{userId}` — administrator-only bulk revocation for a user.

User enrollment and self-service revocation require a credential-password account; passkey-only users receive `409` because no passkey reauthentication ceremony has been added to these management routes. An administrator can revoke a user's devices without their password.

### Account lockdown (implemented)

Emergency account lockdown is implemented per [Account Lockdown](../security/account-lockdown.md), modeled on authentik's account lockdown feature.

- `POST /api/security/account-lockdown` — self-service `{reason}`; the acting session is destroyed as part of the action.
- `POST /api/security/account-lockdown/user/{userId}` — administrator `{reason}`; bans the account (which the D1 triggers use to revoke OAuth tokens), deletes all sessions, replaces the credential password with an unusable hash, removes OPAQUE credentials, and revokes trusted devices, atomically as one D1 batch.
- `POST /api/security/account-lockdown/user/{userId}/unlock` — administrator `{new_password?}`; clears the ban and marks the lockdown lifted. Sessions, tokens, and trusted devices remain revoked; without `new_password` the usable password must be set through `POST /api/auth/admin/set-user-password`. Advise the user to re-verify MFA enrollments.
- `GET /api/security/account-lockdown/user/{userId}` (admin) and `GET /api/security/account-lockdown/self` return the lockdown history with reasons.
- Events: `identity.user.lockdown`, `identity.user.lockdown_lifted` in the audit trail; lockdown reasons are stored in the `account_lockdowns` table.
- Recovery links: `POST /api/security/account-recovery` (admin; requires an active lockdown) issues a single-use, short-lived reset token delivered out of band; `POST /api/security/account-recovery/redeem` (public, rate-limited) consumes it, resetting the password and lifting the recorded lockdown. See [Account Lockdown](../security/account-lockdown.md).

### Session network/GeoIP binding (implemented; disabled by default)

Per [Session Network/GeoIP binding](../security/session-geo-binding.md): sessions are bound at creation to the edge-derived ASN/network/IP digest, country, and city digest (`SESSION_BINDING_MODE`, `SESSION_BINDING_NETWORK`, `SESSION_BINDING_GEOIP`). Observed drift (`observe`) writes `authentication.session.location_drift.observe`; enforcement deletes the session and writes `authentication.session.location_violation`. Evaluation runs on `/api/auth/get-session` and `/api/auth/oauth2/authorize` only. A session without a stored envelope (created before rollout or without edge data) is allowed.

For interactive OAuth authorization, a logged-in browser may provide `fingerprint_event_id` as an authorization query parameter. If OAuth redirects the user through sign-in and drops that query parameter, enforcement will require the authorization request to be resumed with a fresh event; this redirect continuation has not been end-to-end verified. Under `observe`, valid event data is recorded but does not deny authorization. Under `enforce`, missing/invalid/replayed events, untrusted or low-confidence devices, and strong configured risk signals do not result in a usable new authorization result. For password/passkey login, Better Auth creates the D1 session before the Worker makes the risk decision; a denied session is deleted before returning, but this post-creation ordering still needs real-flow verification before production enforcement. Existing sessions are not automatically revoked by these initial rules. A `step_up` decision is handled by the step-up challenge flow described in [Device risk and trusted-device policy](../security/device-risk-and-trust.md): the response carries `stepUpChallenge`, SSO issuance stays withheld until a second factor is verified, and accounts without any enrollable factor keep failing closed (the OPAQUE gate has the same step-up behavior — see [OPAQUE login](#opaque-login-rfc-9807-implemented)). A user blocked on a new device must use an existing authenticated device to enroll it, or go through the administrator-issued recovery link above.

- `GET /api/security/step-up/challenge` — session-authenticated challenge status for the acting session: `{required: false}` when nothing is open or the requirement is satisfied, otherwise `{required: true, state: pending|expired, reasons, expiresAt, methods}`. The challenge is opened automatically by the risk pipeline (`enforce` mode); it is satisfied by completing any session-bound second-factor verification (TOTP, phone/email OTP, backup codes, Duo push, hardware OTP).
- `POST /api/security/account-recovery/redeem` — unauthenticated one-time redemption of an administrator-issued recovery token for a locked account; resets the password and lifts the lockdown atomically. Rate-limited per IP; see [Account Lockdown](../security/account-lockdown.md).
- Session binding evaluation now also covers `/api/auth/oauth2/consent` alongside session validation and authorization.

Initial retention defaults: event replay claims 24 hours, device/network observations 30 days, and risk-decision records and inactive device records 90 days. A daily Worker Cron applies these windows regardless of Fingerprint mode and processes any existing tables even if schema initialization is incomplete. They still need approval by the privacy owner.

## Database initialization

### OIDC sign-in handoff page

- `GET /sign-in?<signed oauth query>` completes the login half of the OIDC authorization-code flow. The authorization endpoint redirects unauthenticated users here; the page signs the user in and posts the tamper-proofed signed query back to the authorization endpoint to continue (consent or code). A visit without the signed continuation responds 400. Same category as the SAML/WS-Federation handoff pages: a protocol completion page, not a portal dashboard.

### Usage snapshot

- `GET /api/admin/usage-snapshot` reports row counts per bounded surface (users, sessions, audit events, OAuth clients and tokens, SWA applications and grants, SAML providers, WS-Federation relying parties, directory groups, SCIM operations) captured at the call time. Administrator session required; read-only numbers only. This is the input for the plan's budget and service-minimization review.

### SWA applications

- `POST /api/admin/swa-applications` registers a Secure Web Authentication application with `{name, origin}`; the origin binds an exact HTTPS origin (no path, credentials, query or fragment) and registrations start disabled. Administrator session, exact `Origin`, audited.
- `GET /api/admin/swa-applications` lists applications; `GET /api/admin/swa-applications/{id}/grants` returns the visible activity view (masked nonces, consumed flags).
- `POST /api/swa/grants` issues a five-minute single-use grant for the acting user at an exact registered, enabled origin; `POST /api/swa/exchange` consumes the nonce atomically once (replays, foreign users, and expired or unknown nonces reject), returning the attestation. The IdP never accepts, stores or logs application credentials; capture stays with the user agent.

### Directory groups

- `POST /api/admin/directory-groups` creates a first-party group with `{name, description?}`; names are 1-64 characters from `[A-Za-z0-9_.-]` and unique. 201 with the group, 409 on a duplicate name. Administrator session and exact `Origin` required; audited.
- `GET /api/admin/directory-groups` lists groups (cursor + `limit` 1-100) without members; `GET /api/admin/directory-groups/{id}` returns the group with up to 500 members and its `attributes`; both are read-only and session-gated.
- `POST /api/admin/directory-groups/{id}/members` grants `{userId}` membership to an existing user (rejects unknown users with 404 and duplicates with 409, both audited); `DELETE /api/admin/directory-groups/{id}/members/{userId}` revokes.
- `DELETE /api/admin/directory-groups/{id}` removes the group, its memberships, and its custom attributes in one atomic D1 batch.
- Groups are claim-release candidates only: protocol assertions do not carry groups until an application binding and release policy exist (see docs/design/directory-groups.md for the open list).

### Accounts (multi-account switching)

- Accounts are tenant-like workspaces one Better Auth user can belong to several of; the active account is a property of the session, not of the user (see docs/design/multi-accounts.md).
- `POST /api/admin/accounts` creates an account with `{name, description?}`; names are 1-64 characters from `[A-Za-z0-9_.-]` and unique; the creator becomes its first `admin` member. 201 with the account, 409 on a duplicate name. Administrator session and exact `Origin` required; audited.
- `GET /api/admin/accounts` lists accounts (cursor + `limit` 1-100); `GET /api/admin/accounts/{id}` returns the account with up to 500 members; both are read-only and session-gated.
- `POST /api/admin/accounts/{id}/members` grants `{userId, role?}` membership (`role` defaults to `member`, `admin` is the other value); rejects unknown users with 404 and duplicates with 409, both audited; `DELETE /api/admin/accounts/{id}/members/{userId}` revokes and drops that member's active-account context for the account in the same batch.
- `PATCH /api/admin/accounts/{id}` updates `{name?, description?}` (409 on a duplicate name) and `PATCH /api/admin/accounts/{id}/members/{userId}` changes `{role}`; both audited (`account.update`, `account.member.role.update`) and both refuse to demote or remove the last `admin` member of an account (409).
- `DELETE /api/admin/accounts/{id}` removes the account with its memberships, session contexts, and custom attributes in one atomic D1 batch.
- `POST /api/admin/accounts/{id}/invitations` mints a single-use opaque join token (`{role?, ttlDays?}`, default `member`/7 days, capped at 30) returned in full exactly once; `GET .../invitations` lists pending/consumed/expired with masked prefixes; `DELETE .../invitations/{token}` revokes a pending one. The daily Worker Cron prunes invitations 31 days after expiry.
- `POST /api/accounts/join` (session, same-origin, audited `account.joined`) redeems `{token}` and grants the invited role; single-use in one D1 batch, member users abort before the write so the token survives, and every rejection (invalid/expired/revoked/replayed/already-member) is one identical 403.
- `GET /api/accounts` (session-gated, no-store) lists the acting user's memberships with the account summaries, roles, and the session's `activeAccountId`.
- `POST /api/accounts/switch` binds `{accountId}` to the calling session: same-origin only, audited (`account.switched`), membership-verified; 403 for a nonexistent or non-membered account without distinguishing the two.
- Per-account authorization: `requiredAccount` on an app-access policy additionally requires the user to hold membership in that account; the account gate precedes the group gate, respects `enforcement_mode`, and is never bypassed by access-request grants.
- Issued tokens do not carry the account by default: with `ENABLE_ACCOUNT_CLAIMS=true` the session's active account is released as a namespaced claim on OIDC access/ID tokens (and UserInfo), on the JWT plugin payload, and as SAML 2.0/WS-Federation attribute URNs at `/saml/sso` and `/wsfed/signin`. The release is fail-closed (undocumented flags yield byte-identical tokens) and only binds accounts the token's own session actually switched into (see docs/design/multi-accounts.md).

### Custom object attributes

- Operators attach custom attributes (a flat JSON object of primitive values) to `user`, `group`, and `account` objects; one set per object in `object_attributes`. Bounds: keys 1-64 characters from `[A-Za-z0-9_.:-]`, string values ≤ 512 characters without control characters, finite safe-integer numbers, booleans, null; at most 32 entries serialized to ≤ 4096 bytes (see docs/design/object-attributes.md).
- `GET /api/admin/attributes/{objectType}/{objectId}` returns `{attributes, updatedAt}` (404 when the object does not exist; 400 on an unsupported type); `PUT` with `{attributes}` replaces the whole set and removes absent keys (empty set clears the row); `DELETE` is idempotent. Administrator session and exact `Origin` for writes; audited (`attributes.set`, `attributes.delete`).
- Attributes are supplementary operator data, never a second copy of Better Auth identity fields. With `ENABLE_ATTRIBUTE_CLAIMS=true` the acting user's attributes are released as a namespaced claim on OIDC access/ID tokens and the JWT payload, and as per-key SAML 2.0/WS-Federation attribute URNs at `/saml/sso` and `/wsfed/signin`; fail-closed.
- Per-application claim release policy: `GET/PUT/DELETE /api/admin/claim-release-policies/{subject}` with `{allowAccountClaims?, allowUserAttributes?}` narrows which released claim kinds reach that application (an AND with the global flags; absent keys default to allowed, no row keeps flag-only behavior). Same subject namespace as app-access policies; audited (`claim.policy.update`, `claim.policy.delete`).
- Inbound SCIM carries user attributes as the `urn:solixcorp:scim:1.0:CustomAttributes` extension: supplied on User create/PUT (validated, 400 on violation, extension replaces the whole set) and replaced/removed through PATCH on the extension path, returned on GET (`/scim/v2/Users` and `/{id}`); the extension appears in `schemas` only when the user has attributes.
- Outbound SCIM release, `ENABLE_SCIM_ATTRIBUTE_RELEASE=true`: `create` and `update` operations on `/api/admin/scim-operations` deliver the user's custom attributes to the target as the same extension (`update` as a path-scoped PATCH operation; `deactivate` never carries profile data). Fail-closed default; a deliberate per-target operator decision, and attribute changes surface only on the next manually triggered operation (no automatic lifecycle trigger exists).

### Access requests (just-in-time application access)

Requests let a user ask for time-limited access to an application instead of an administrator editing access-policy groups; approval grants expire automatically (see docs/design/access-requests.md). Policy subjects are the same protocol-qualified strings as app-access policies.

- `POST /api/admin/access-request-rules` creates a rule `{name, minReviewers?, notifyMode?, reviewerUsers?, reviewerGroups?}` (reviewers decide; an empty set leaves the request with nobody who can approve). Administrator session, audited.
- `GET /api/admin/access-request-rules` lists rules; `DELETE /api/admin/access-request-rules/{id}` removes an unbound rule (409 while still bound).
- `POST /api/admin/access-request-bindings` makes an application requestable: `{subject, ruleId, pendingExpirySeconds?, maxGrantedExpirySeconds?, requesterUsers?, requesterGroups?}` — an empty requester set is open to every user, the subject is unique, and granted access can never outlive `maxGrantedExpirySeconds`. Audited.
- `GET /api/admin/access-request-bindings` lists bindings; `DELETE /api/admin/access-request-bindings/{id}` removes one.
- `GET /api/admin/access-requests?status=` lists requests (filter pending/approved/denied/cancelled/lapsed/revoked); `POST /api/admin/access-requests/{id}/revoke` ends that request's active grant early.
- User surface (session, same-origin on mutation): `GET /api/access-requests/requestable` (Discover list), `POST /api/access-requests` `{subject, justification, requestedExpirySeconds?}` (one pending request per user and subject), `GET /api/access-requests/me`, `POST /api/access-requests/{id}/cancel`, `GET /api/access-requests/reviews` (reviewer queue), `POST /api/access-requests/{id}/review` `{decision: approved|denied, note?}`. The requester can never review their own request; denial is immediate, approval accumulates until the rule's minimum-approver count.
- Lifecycle events (`access_request.created/approved/denied/cancelled/revoked`) are tamper-evident audit rows; reviewer notification is a best-effort webhook (`ACCESS_REQUEST_WEBHOOK_URL`) and the review queue stays authoritative.

### SAML and SCIM preparation

- `POST /api/admin/saml-service-providers` registers an SP configuration in a disabled state; administrators supply `entityId`, `acsUrl` and `signingCertificate`. Requires an administrator session, exact configured `Origin`, and application schema migration. This does not enable SAML sign-in.
- `DELETE /api/admin/saml-service-providers/{id}` removes a disabled registration; an enabled one must be disabled first (409 otherwise). Administrator session, exact `Origin`, audited.
- `GET /api/admin/saml-service-providers/{id}` retrieves an SP registration for an administrator. Certificate syntax is checked but X.509 validity and interoperability are not yet verified.
- `GET /api/admin/saml-service-providers` lists registrations with optional `limit` (1–100) and `cursor`; the list omits certificates.
- `GET /api/admin/scim-operations/{id}` retrieves one outbound operation journal entry for an administrator.
- `POST /api/admin/scim-operations` manually executes `create`, `update`, or `deactivate` for an existing local `userId`. Requires an administrator session, exact configured `Origin`, application migration, and `ENABLE_SCIM_PROVISIONING=true` with a single `SCIM_TARGET_ID`, HTTPS `SCIM_BASE_URL`, and secret `SCIM_BEARER_TOKEN`. The request cannot select a URL or credential. A returned `operationId` supports reconciliation; unknown results block subsequent operations for that target/user and must not be blindly retried. No automatic lifecycle trigger or reconciliation endpoint is provided yet.

- `POST /api/admin/saml-service-providers/{id}/enable` enables a verified registration: the stored certificate must import into a usable RSA verify key. Requires an administrator session, the exact configured `Origin`, and is audited. `POST /api/admin/saml-service-providers/{id}/disable` always disables.
- `GET /saml/metadata` publishes IdP metadata (entityID, signing certificate, SSO endpoints) from the configured signing material, or 503 when it is not configured.
- `GET /saml/sso` runs the gated chain: enabled registration → certificate-derived key → redirect binding signature over received bytes → full revalidation → user session (an unauthenticated visitor gets a same-origin sign-in page that reloads the original request after success) → one-time replay claim → signed Response delivered by an auto-submitting POST form to the registered ACS. It responds 503 without IdP signing material and 401 for issuers without an enabled registration.

See [SAML status](../feasibility/saml-backend-status.md) and [SCIM status](../feasibility/scim-connector-status.md). No SAML login is reachable in practice: `GET /saml/sso` exists but requires an enabled registration, configured IdP signing material, and a verifiable signed request; sign-in ends in an error response until those deliberate decisions are made. No automatic SCIM provisioning is enabled. Do not enable outbound provisioning against a production target before target-specific mapping, privacy and security review.

### `POST /_internal/migrate`

Not found unless `ENABLE_MIGRATIONS=true` and `MIGRATION_TOKEN` are configured. The run is audited as `admin.migration.executed` (no session actor, token-protected route); a first-run migration writes the audit after creating the schema, so a missing audit row only applies to the very first run. Requires `Authorization: Bearer <MIGRATION_TOKEN>`. Runs Better Auth D1 schema migrations and creates the application audit, Fingerprint event-claim, trusted-device, risk-decision, and lookup-budget tables/indexes. Prefer a one-time operator-controlled deployment window; disable and remove the token afterward. Do not expose the route publicly or place its token in a repository.

## Backend implementation notes

- Better Auth, the OAuth provider, passkey, username, and admin plugins are instantiated against the request's Worker bindings; no separate application service or runtime is introduced.
- New passwords use a version-tagged WebCrypto PBKDF2-SHA-256 hash configured in the Worker; legacy Better Auth scrypt hashes remain verifiable. Reassess the KDF and Worker CPU/latency with security review before production, and avoid switching algorithms without preserving existing verifiers.
- The admin create-user endpoint creates the user and password hash but does not create a session or send email. Employee invitation, first-login verification, password reset, and recovery delivery are not implemented yet.
- Use `bun run dev` for local Worker execution, `bun run typecheck` for a quick static check, and `bun run build:check` for Wrangler bundle validation. No test-code directory or test command is maintained by request.
- D1 has no interactive transactions. Do not describe related sign-in/reset/token operations as fully transactional until the adapter's `batch()` behavior and concurrent single-use-token handling are established. The SCIM plugin also requires interactive transactions and therefore is not a supported D1 integration path without another Workers-compatible implementation.
- D1 rate-limit persistence shares the database with auth and audit writes. Quota, contention, and cost need observation before setting production thresholds.

## Not implemented by this API draft

SAML IdP, SCIM 2.0 provisioning, WS-Federation, Secure Web Authentication, live Tailscale OIDC integration (the email domain is recorded; the disposable test tenant and live run are pending), email delivery/reset workflows, MFA policy, group/role claims, key backup/rotation operations, and external-app session termination remain open. Account/attribute claim release is implemented behind the operator flags (with per-application release policies). The optional WebFinger route is present but requires domain routing and live interoperability validation. Fingerprint event verification, login risk checks, D1 replay claims, short-lived trusted-device records, password-confirmed device management, independent recovery, the step-up challenge flow and the R2 independent audit backup (docs/security/audit-backup.md) are implemented behind explicit configuration, but still need real Fingerprint credentials, D1 concurrency verification, and measured false-positive/cost review before production enforcement. Do not claim protocol compatibility until a Workers-compatible implementation path and target-service interoperation have been demonstrated.
