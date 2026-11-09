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
- `POST /api/auth/token` — disabled to avoid exposing a second, unrelated JWT token-issuance path.

The authorize flow redirects unauthenticated users to `/sign-in` and users needing consent to `/consent`. These are relying-party/browser return locations, not routes implemented by this Worker; a separate client is required before interactive OIDC can complete. No frontend is included. Confirm the selected OIDC profile, PKCE behavior, logout semantics, claims mapping, and real test-RP interoperability before production.

## User lifecycle and session revocation

The Better Auth admin plugin supplies authenticated/authorized account-management operations under `/api/auth/admin/*`, including create/list/update users, ban/unban, and user/session revocation. The first administrator is created by the gated bootstrap route with the `admin` role; no administrator ID is hard-coded in Worker configuration. Create an employee with `POST /api/auth/admin/create-user` (`email`, `name`, `password`, and `data: { username }`); only the application retains the initial password, while the API stores its password hash. This plugin route returns HTTP 200 on successful creation.

- Disable an employee with `POST /api/auth/admin/ban-user` (`userId`, optional `banReason`): Better Auth blocks new sign-ins and deletes the user's IdP sessions as part of the ban operation. Verify the behavior and D1 failure semantics in the deployed environment.
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

Configuration: set `FINGERPRINT_MODE=observe|enforce`, `FINGERPRINT_REGION=us|eu|ap`, and the Worker secret `FINGERPRINT_SERVER_API_KEY`. Optional controls are `FINGERPRINT_MIN_CONFIDENCE` (default `0.7`), `FINGERPRINT_SUSPECT_SCORE_THRESHOLD` (unset unless deliberately selected), `FINGERPRINT_MAX_EVENT_AGE_SECONDS` (default `120`), and `FINGERPRINT_ALLOWED_ORIGINS` (comma-separated additional event origins). Do not configure production thresholds without a false-positive review.

- `GET /api/security/trusted-devices` — list the current user's trusted devices, including revoked/expired state.
- `POST /api/security/trusted-devices` — enroll a device. Requires `event_id`, current `password`, and optional `label`; the event must be fresh, verified, unused, and sufficiently confident. Device trust expires after 30 days.
- `DELETE /api/security/trusted-devices` — revoke all current user's devices; requires current password confirmation.
- `DELETE /api/security/trusted-devices/{deviceId}` — revoke one of the current user's devices; requires current password confirmation.
- `DELETE /api/security/trusted-devices/user/{userId}` — administrator-only bulk revocation for a user.

User enrollment and self-service revocation require a credential-password account; passkey-only users receive `409` because no passkey reauthentication ceremony has been added to these management routes. An administrator can revoke a user's devices without their password.

For interactive OAuth authorization, a logged-in browser may provide `fingerprint_event_id` as an authorization query parameter. If OAuth redirects the user through sign-in and drops that query parameter, enforcement will require the authorization request to be resumed with a fresh event; this redirect continuation has not been end-to-end verified. Under `observe`, valid event data is recorded but does not deny authorization. Under `enforce`, missing/invalid/replayed events, untrusted or low-confidence devices, and strong configured risk signals do not result in a usable new authorization result. For password/passkey login, Better Auth creates the D1 session before the Worker makes the risk decision; a denied session is deleted before returning, but this post-creation ordering still needs real-flow verification before production enforcement. Existing sessions are not automatically revoked by these initial rules. There is no separate MFA/OTP step-up flow yet, so a step-up decision is fail-closed rather than granted. A user blocked on a new device must use an existing authenticated device to enroll it or go through the organization's account-recovery process; that recovery flow is not part of this API.

Initial retention defaults: event replay claims 24 hours, device/network observations 30 days, and risk-decision records and inactive device records 90 days. A daily Worker Cron applies these windows regardless of Fingerprint mode and processes any existing tables even if schema initialization is incomplete. They still need approval by the privacy owner.

## Database initialization

### SWA applications

- `POST /api/admin/swa-applications` registers a Secure Web Authentication application with `{name, origin}`; the origin binds an exact HTTPS origin (no path, credentials, query or fragment) and registrations start disabled. Administrator session, exact `Origin`, audited.
- `GET /api/admin/swa-applications` lists applications; `GET /api/admin/swa-applications/{id}/grants` returns the visible activity view (masked nonces, consumed flags).
- `POST /api/swa/grants` issues a five-minute single-use grant for the acting user at an exact registered, enabled origin; `POST /api/swa/exchange` consumes the nonce atomically once (replays, foreign users, and expired or unknown nonces reject), returning the attestation. The IdP never accepts, stores or logs application credentials; capture stays with the user agent.

### Directory groups

- `POST /api/admin/directory-groups` creates a first-party group with `{name, description?}`; names are 1-64 characters from `[A-Za-z0-9_.-]` and unique. 201 with the group, 409 on a duplicate name. Administrator session and exact `Origin` required; audited.
- `GET /api/admin/directory-groups` lists groups (cursor + `limit` 1-100) without members; `GET /api/admin/directory-groups/{id}` returns the group with up to 500 members; both are read-only and session-gated.
- `POST /api/admin/directory-groups/{id}/members` grants `{userId}` membership to an existing user (rejects unknown users with 404 and duplicates with 409, both audited); `DELETE /api/admin/directory-groups/{id}/members/{userId}` revokes.
- `DELETE /api/admin/directory-groups/{id}` removes the group and its memberships in one atomic D1 batch.
- Groups are claim-release candidates only: protocol assertions do not carry groups until an application binding and release policy exist (see docs/design/directory-groups.md for the open list).

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

SAML IdP, SCIM 2.0 provisioning, WS-Federation, Secure Web Authentication, live Tailscale OIDC integration, email delivery/reset workflows, MFA policy, group/role claims, key backup/rotation operations, one-year audit backup/immutability, and external-app session termination remain open. The optional WebFinger route is present but requires domain routing and live interoperability validation. Fingerprint event verification, login risk checks, D1 replay claims, short-lived trusted-device records and password-confirmed device management are implemented behind explicit configuration, but still need real Fingerprint credentials, D1 concurrency verification, independent recovery/step-up, and measured false-positive/cost review before production enforcement. Do not claim protocol compatibility until a Workers-compatible implementation path and target-service interoperation have been demonstrated.
