# Production deployment checklist (Phase 6)

**Status:** the runbook for the first production deployment. Every step is deliberately gated; the two bootstrap/migration endpoints stay disabled outside their one-time windows.

## 1. Pre-deployment (operator, once)

- **Secrets.** Provision as Wrangler secrets, never in the repository:
  - `AUTH_SECRET` (≥ 32 bytes, unique)
  - `AUTH_BASE_URL` (the production HTTPS origin, no path)
  - `MIGRATION_TOKEN`, `ADMIN_BOOTSTRAP_TOKEN` (≥ 32 bytes each; used once, then disabled)
  - `CLIENT_REGISTRATION_TOKEN` if dynamic client registration is wanted at launch
  - `SAML_IDP_ENTITY_ID` + `SAML_IDP_SIGNING_CERTIFICATE` + `SAML_IDP_SIGNING_PRIVATE_KEY` — generate with `bun run scripts/generate-saml-key.ts`; keep the private key in the secret store only
- **Flags in `wrangler.jsonc`/vars:** leave `ENABLE_MIGRATIONS`, `ENABLE_ADMIN_BOOTSTRAP`, `ENABLE_DYNAMIC_CLIENT_REGISTRATION` set to `false` in the committed config; enable them only as temporary deployment-window overrides.
- **DNS.** The email-domain route for Tailscale WebFinger (`/.well-known/webfinger` on the company domain) is only needed when that integration goes live. Live validation is unblocked as of 2026-11-10: `auth.solixllc.com` is the selected company email domain (QST-1794159222-ane decision) — configure `OIDC_EMAIL_DOMAIN=auth.solixllc.com`, point WebFinger routing for that domain at this Worker, and provision the disposable Tailscale test tenant when the live run is scheduled.
- **Audit backup.** The `deploy` script provisions first: `predeploy` runs `scripts/ensure-audit-backup-bucket.ts`, which creates the bucket named in `wrangler.jsonc` (`internal-auth-audit-backup`, idempotent) and verifies it (docs/security/audit-backup.md). `POST /api/admin/bootstrap` also reports `checks.auditBackupR2` so the bootstrap window confirms the binding resolved. Manual fallback: `bun run provision:r2`.
- **Application icons.** `wrangler.jsonc` binds the R2 bucket `internal-auth-application-icons` as `APPLICATION_ICONS`; `predeploy` creates it together with the audit-backup bucket (idempotent). Without the binding, icon upload answers 400 and icon serving 404.
- **Review gates that remain owner decisions:** MFA policy, recovery channel, production SAML/SCIM target applications (pending owner selection; registration APIs are implemented and ready).

## 2. Deployment window

1. `wrangler deploy` with the temporary override flags (`ENABLE_MIGRATIONS=true`, `ENABLE_ADMIN_BOOTSTRAP=true`).
2. Create the D1 schema: `POST /_internal/migrate` with the migration bearer token — one call; the response records an `admin.migration.executed` audit event.
3. Create the first administrator: `POST /api/admin/bootstrap` — one call (409 afterwards by design); requires the configured `Origin`. Password sign-in is closed in production (`ALLOW_PLAINTEXT_PASSWORD_LOGIN` unset), so the new account cannot sign in yet. The response carries `activation.url` (shown once, valid for the activation TTL, 24 h by default): open it in a browser and set the real password, which registers the OPAQUE credential. The `password` sent in the bootstrap body is only a placeholder; use a random value and discard it. Requires `OPAQUE_MASTER_KEY` and `AEAD_SEALING_KEY`. **Use the link before it expires.** If it expires, bootstrap cannot be repeated (409, a user exists) and re-issuing a link needs an administrator session, which does not exist yet. There is no built-in way out: the only recovery is to wipe the D1 database (or delete the `user`, `bootstrap_state` and related rows) and run the window again. Raise the link lifetime in the settings page only after the first sign-in, so run the window while you can finish it in one sitting.
4. Verify the protocols headlessly against production: copy `scripts/run-all-smokes.ts` invocation with production `--base`, fresh migration/bootstrap disabled (they are one-time), and the operator credential — expect the five smokes to pass with the same assertions as local.
5. **Close the window:** redeploy with the override flags back to `false`. Confirm `/_internal/migrate` and `/api/admin/bootstrap` return 404 (`bun run verify:web --base $ORIGIN` checks this, together with the SPA headers and routes).

### 2a. Checks for the web app (`web/`), once, right after the first deploy

`bun run build:check` is the dry run; `bun run deploy` builds `web/` and uploads it as static assets of the same Worker. `bun run verify:web --base $ORIGIN` runs items 1 to 3 and the closed-door checks without signing in (add `--window-open` while the migrate and bootstrap flags are still on; it exits non-zero on any failure). The manual items below are what it cannot do. Replace `$ORIGIN` with the real origin:

1. SPA routes return the app shell and reload cleanly: `curl -s -o /dev/null -w "%{http_code} %{content_type}\n" $ORIGIN/login $ORIGIN/security $ORIGIN/admin/users` expects `200 text/html` for each.
2. `web/public/_headers` took effect: `curl -sI $ORIGIN/` must show `content-security-policy`, `x-frame-options: DENY` and `strict-transport-security`; `curl -sI $ORIGIN/assets/<hashed file>` must show `cache-control: public, max-age=31536000, immutable`. If they are missing, static headers are not applied and the SPA is served without a CSP.
3. Backend paths still reach the Worker: `curl -s -o /dev/null -w "%{http_code}\n" $ORIGIN/health` is 200 and `$ORIGIN/auth/login` redirects (302) to `/oauth2/v1/authorize`. Every path in `run_worker_first` must stay in sync with `BACKEND_PATHS` in `web/vite.config.ts`. The current lists cover `/api`, `/.well-known`, `/saml`, `/wsfed`, `/scim`, `/sign-in`, `/auth`, `/oauth2`, `/enduser`, `/idp`, `/health`, `/dev`, `/_internal` and `/application`: Wrangler uses `/*` descendants except for the exact `/sign-in` and `/health` entries; Vite uses segment-boundary prefixes for local proxying.
4. Sign in as the first administrator from the activation link above, then open users, settings, policies and the security page; the browser console must show no Content-Security-Policy violation.
5. Fingerprint, after the keys are set (`FINGERPRINT_SERVER_API_KEY`, `FINGERPRINT_PUBLIC_API_KEY`): keep `fingerprint.mode` at `observe` in the settings page, sign out and in once, and watch the console for CSP violations. The policy allows the loader host `fpnpmcdn.net`, `*.fpjs.io` and `*.workpass.solixllc.com` (the custom subdomain in `FINGERPRINT_ENDPOINT`). If you use another subdomain, change `script-src` and `connect-src` in `web/public/_headers` and redeploy. Switch to `enforce` only after the admin's own device check shows up (the settings page refuses otherwise).
6. Mail: with the mail provider configured, create a user from the users page with "send email" and check `account.invitation.email` in the audit log. Without a provider the page shows the link once instead.

## 3. Post-deployment verification (Phase 6's deferred half)

- Cross-isolate concurrency probes: repeat the eight-way SAML claim race and the unique-name directory race against production; expect the same one-winner semantics shown locally.
- CPU accounting: measure the PBKDF2 sign-in wall time in production and compare against the selected plan's limit; the 50–61 ms local wall time is the reference, not a result.
- OAuth consent + userinfo against a real relying party; SAML/WS-Federation round trips with the first real SP/rp.
- Budget review: Workers request/CPU/D1 row counts against the free-tier thresholds recorded in the plan; decide paid-plan needs explicitly.

## 4. Rollback and recovery

- Worker: `wrangler rollback` (deployment-level); the D1 schema is forward-only by design — migrations are additive (`CREATE IF NOT EXISTS` + additive ALTER), so a worker rollback never needs a schema rollback.
- Data: D1 Time Travel (30 days) is the recovery mechanism; it is NOT the one-year audit-backup requirement — the backup design remains the recorded open question.
- Break-glass: the bootstrap and migration endpoints fail closed when their flags are off; re-enabling them is a deliberate redeploy.

## 5. Known limits at first deploy

- Audit tamper-evidence is detection-only (content hashes + log positions); D1 is not immutable.
- WS-Federation/SAML/SWA tokens are opaque bearer artifacts; replay protection is party-side per the documented profiles.
- The MFA policy, recovery channel and test SaaS targets are pending owner decisions recorded in the plan.

## Platform configuration (2026-11)

The following wrangler.jsonc platform settings are in force; verify them at deploy:

- `compatibility_date: 2026-11-09` with explicit
  `compatibility_flags: ["nodejs_als"]` — narrow AsyncLocalStorage support,
  not full Node.js compatibility.
- `workers_dev: false` — internal IdP is served by a configured route only.
- `upload_source_maps: true` — stack traces in Workers Logs resolve to source.
- `observability.enabled: true` with `logs.enabled: true`,
  `logs.head_sampling_rate: 1` and `logs.invocation_logs: true` — request logs
  are enabled at full sampling with `logs.storage.retention_days: 30`;
  traces are enabled separately at `traces.head_sampling_rate: 0.01`.
- `limits: { cpu_ms: 5000, subrequests: 1000 }` — runaway-cost protection with
  generous headroom (SAML RSA signing and OIDC crypto stay in single-digit ms).
- `placement: { mode: "smart" }` — Smart Placement co-locates execution with
  D1, Fingerprint and Duo server APIs; monitor with the `cf-placement` header.
- SAML metadata endpoints are edge-cached for 60 s (`caches.default`), which is
  also pass-through-safe on workers.dev. **Key rotation note:** after rotating
  the SAML signing secret, SP metadata refreshes within 60 s; force a refresh
  immediately `cache.delete` by requesting metadata once after deployment.

## Credential & storage protection posture (2026-11)

- Transport: TLS 1.3 terminates at the edge; credential payloads (passwords,
  session cookies, bearer tokens) must never be transmitted unencrypted and
  the Worker must not be served without HTTPS routes.
- Passwords: hashed scrypt via Better Auth — never stored or logged plaintext
  and never reversible.
- Material at rest in D1 is AEAD-sealed (`src/crypto/sealed.ts`):
  `SEALED_STORAGE_CIPHER` selects the write cipher — `xchacha20poly1305`
  (default, @noble/ciphers, audited, workerd-verified) or `aes256gcm`
  (AES-256-GCM via WebCrypto, 96-bit IV + 128-bit tag per NIST SP 800-38D;
  the FIPS-aligned selection for approved-algorithm deployments). Requires
  `AEAD_SEALING_KEY` (32 bytes, base64). Fail-closed: without the key,
  sealing operations abort instead of storing plaintext. Envelope reads are
  version-driven (`v1` XChaCha, `v2` AES-GCM), so switching ciphers never
  strands existing rows; rows re-seal lazily on first successful use while
  legacy plaintext rows migrate on first read.
- Documented exceptions to the approved-algorithm profile: HOTP (RFC 4226)
  HMAC-SHA-1 is mandated by the token standard, and the Duo Auth API signing
  contract is SHA-1 by vendor specification (the platform's own tokens use
  SHA-256).
- MFA sub-router is mounted under /api (`app.route("/api", mfaRoutes)`);
  /api/mfa/* endpoints return 401 (not 404) without a session.
- HOTP secrets are canonical RFC 4648 base32 (32 chars for a 20-byte key) so
  hardware tokens can load them; verification decodes canonically.

## OPAQUE (RFC 9807) zero-password authentication (2026-11)

**Active (2026-11):** OPAQUE routes are served again. Every login now runs
through the shared gate (`src/auth/opaque-login.ts`) before a session issues:

- banned accounts (and accounts whose row cannot be read) are denied,
- the device-risk pipeline matches password/username/passkey logins: clients
  may submit `fingerprint: { event_id }` at `/api/opaque/auth/start` (sealed
  results are rejected); in `enforce` mode the session is withheld on a
  missing/unverifiable event, a replay, or a deny/step_up risk action; in
  `observe` mode outcomes are recorded best-effort and never block baseline
  authentication,
- denials audit `authentication.opaque.login` with outcome `failure`,
- `requireMfa` application policies still apply to OPAQUE sessions the same
  way as passkey sessions: no proof is minted at login, so restricted apps
  require a step-up verification through one of the proof-recording
  endpoints first.
- **MFA session proofs (2026-11):** `requireMfa` policies honor only
session-bound proofs (`session_mfa_proofs`), recorded on successful
`/two-factor/verify-totp`, `/two-factor/verify-otp`,
`/two-factor/verify-backup-code`, `/api/mfa/hotp/verify`, and
`/api/mfa/duo/verify` (`result: allow`). Enrollment alone satisfies nothing;
a trust-device cookie that bypasses the challenge does not mint a proof — such
sessions must step up through a verification endpoint first. Proof rows are
removed by the daily cron after 31 days.

- @cloudflare/opaque-ts over OPAQUE_P256; the password never leaves the
  browser and the platform stores no password, hash, or password-derived
  value (the credential record is itself password-protected, plus sealed
  with the platform AEAD at rest).
- Endpoints: /api/opaque/register/start|finish (session-bound enrollment)
  and /api/opaque/auth/start|finish (public login, rate-limited 30/min/IP,
  single-use 2-minute transcripts, user-enumeration-resistant fake record).
- Server material: OPRF seed HKDF-derived from OPAQUE_MASTER_KEY (secret,
  32 bytes base64); AKE keypair generated once and stored SEALED in
  opaque_server_material. Rotation requires a fresh OPAQUE_MASTER_KEY and
  re-enrollment of every credential record.
- Legacy plaintext password sign-in fails closed unless `ALLOW_PLAINTEXT_PASSWORD_LOGIN=true`
  is explicitly set; leave it unset in production. Enroll OPAQUE per user
  (the smoke scripts/opaque-smoke.ts demonstrates the flow).

## Device-risk hardening: GeoIP history, step-up, session binding, lockdown (2026-11)

Implemented across `src/security/` and documented in
[device risk policy](../security/device-risk-and-trust.md),
[session-geo-binding.md](../security/session-geo-binding.md) and
[account-lockdown.md](../security/account-lockdown.md). Rollout order:

1. MFA coverage first. In `enforce` mode, accounts without any enrollable
   second factor fail closed on `step_up` decisions. Check
   `session.twoFactorEnabled` / hardware-token / Duo coverage before tightening.
2. `FINGERPRINT_MODE=observe` with the GeoIP history knobs at defaults
   (`GEOIP_HISTORY_LOGIN_COUNT=5`, impossible travel on with the built-in
   1,000 km/h allowance, history distance off). Review
   `authentication.fingerprint.risk_*` audit events for false positives
   before touching thresholds.
3. `SESSION_BINDING_MODE=observe` (network `asn`, GeoIP `country`) and read
   `authentication.session.location_drift.observe` events; tighten to
   `asn_and_ip` / `country_and_city` only when drift matches real movement.
4. Switch to `enforce` gradually: risk decisions (`step_up` opens a
   `stepUpChallenge` requiring a second factor before SSO issuance —
   status at `GET /api/security/step-up/challenge`), then session binding.
5. Keep the emergency paths ready: account lockdown
   (`POST /api/security/account-lockdown*`), unlock, and admin-issued
   one-time recovery links (`POST /api/security/account-recovery`,
   redeem at `/api/security/account-recovery/redeem`). There is no email
   infrastructure; recovery tokens are delivered out of band and expire in
   60 minutes by default.

Standing caveats: `request.cf` supplies ASN/geo for session binding — never
trust client-forwarded headers for it; the OPAQUE path participates in
step-up and lockdown but its sessions are not geo-bound (no edge context at
session creation); downstream application sessions cannot be revoked by the
IdP and must not be described as terminated.

## OAuth 2.0 Token Exchange (RFC 8693) (2026-11)

Enabled only on a worker running with `ENABLE_TOKEN_EXCHANGE=true`; the grant
`urn:ietf:params:oauth:grant-type:token-exchange` is served at the standard
`/api/auth/oauth2/token` endpoint through the OAuth provider extension.

Profile rules (all enforced server-side, default deny):
- Confidential clients only (client_secret/basic; public clients denied).
- Explicit allowlist `TOKEN_EXCHANGE_ALLOWED_RESOURCES` → per-client target
  resources; anything missing or malformed is denied.
- Client authentication is mandatory; a sender-constrained subject (`cnf`)
  cannot be exchanged because the profile cannot carry the constraint.
- Subject: the platform's own active access token (opaque or RFC 9068
  `at+jwt`) bound to a live session (`sid`); account-banned users denied.
- Scope narrowing only: requested scopes must be a subset of the subject's;
  `openid`/`offline_access` are never issued through exchange (no ID/refresh
  tokens minted by this grant); `actor_token` (delegation chains) rejected.
- Lifetime: the target resource's configured `accessTokenTtl` (from
  `OAUTH_RESOURCES`) must be shorter than the subject's remaining life plus a
  safety margin, or the exchange is denied — a delegation can never outlive
  the subject. Seed a short-TTL delegated resource explicitly as the target.
- Every authorized exchange is audited
  (`authentication.token_exchange.authorized`); if the audit write fails the
  token is not minted.

Integration verified in `tests/token-exchange-flow.test.ts` (real server, in-memory
DB: registration → authorize/consent → mint → exchange → failure paths) and by
`scripts/token-exchange-smoke.ts` against a running worker.

## OAuth 1.0a server (RFC 5849, HMAC-SHA1 profile) (2026-11)

Enabled only with `ENABLE_OAUTH1=true`; every `/api/oauth1/*` route fails
closed otherwise. `OAUTH1_MANAGEMENT_TOKEN` (>= 32 bytes) is required.
- Consumer registration: `POST /api/oauth1/consumers` (operator bearer token)
  returns the consumer key/secret once; secrets and all token secrets are
  sealed at rest with the platform AEAD (`AEAD_SEALING_KEY` required).
- Three-legged flow: `POST /api/oauth1/initiate` (HMAC-SHA1, consumer-only,
  callback validated, 10-minute temporary credentials) → browser
  `GET /api/oauth1/authorize?oauth_token=…` → signed-in user approves/denies →
  verifier delivered by callback redirect (or shown for `oob`) →
  `POST /api/oauth1/token` (consumer + temp-token signature, single-use
  verifier) issues a long-lived access token.
- Replay protection: HMAC-SHA1 verified with Web Crypto, nonces consumed
  atomically in `oauth1_nonce_claims` (unique key), temporary credentials are
  single-use receipts. Signature base normalizes per RFC 5849; protocol
  parameters must arrive in the Authorization header (body protocol params are
  rejected to remove ambiguity).
- Revocation/offboarding: `POST /api/oauth1/token/revoke`, disabled consumers,
  and `revokeOAuth1UserTokens` called after an administrator bans a user.
  Administrator deletion is currently disabled.
- Audited: consumer register/enable/disable, temporary issue, approve/deny,
  access issue/revoke. Access-token requests are rate-limit candidates for a
  later pass (not yet wired).

## Shared Signals Framework (OpenID SSF 1.0) (2026-11)

Receiver: `ENABLE_SSF_RECEIVER=true` + `SSF_STREAMS` (operator-pinned issuer,
audience, JWKS, event types, optional shared delivery token).
- `POST /api/ssf/receiver/:streamId` accepts `application/secevent+jwt`;
  verifies RS256 signature against pinned keys only, issuer/audience/event
  type/jti/iat constraints, atomically queues the SET (`ssf_inbox`) and
  replies 202; duplicates accepted idempotently. Every queueing also writes a
  receiver audit event; if the audit write fails the sender gets 503.
- The inbox is deliberately inert: it does NOT affect accounts. Consuming
  events (session revocation etc.) requires a dedicated, reviewed handler
  that validates the event-specific subject — not wired yet, so incoming
  signals are durably recorded but not acted on.

Sender: `ENABLE_SSF_SENDER=true`; `SSF_MANAGEMENT_TOKEN` gates recipient
registration (`POST/DELETE /api/SSF/… /api/ssf/streams`) and explicit dispatch
(`POST /api/ssf/events`). Outbound SETs are signed with a generated RS256 key
(sealed at rest; public JWKS at `/api/ssf/jwks.json`, kid `ssf-1`). Delivery is
recorded per attempt with bounded retry (10 attempts, exponential backoff,
abandoned states never silently dropped; scheduled waves retry `retry` rows).
Custom object attribute changes are wired now: user/group/account attribute
writes emit `urn:solixcorp:internal-auth:attributes-changed:1.0` (subject
`{"user": {"user_id": …}}`) to every recipient whose registered `event_types`
include the URN. Recipients that do not list it are never contacted, so
registering a recipient without the URN keeps the pre-attribute behavior.

Verified in `tests/oauth1-flow.test.ts`, `tests/ssf-flow.test.ts`, and
`tests/ssf-attribute-events-and-mocks.test.ts` (real router, in-memory DB).
No external-interop testing has been performed.

## Device Authorization Grant (RFC 8628) (2026-11)

`ENABLE_DEVICE_FLOW=true`; otherwise every `/device` route 404s and the grant
is absent from discovery. Full flow in `docs/design/device-flow.md`.
- `POST /api/auth/oauth2/device/authorize` (public): client must be registered
  with the device_code grant; requires `scope` ⊆ registered scopes; 20 active
  grants per client max. Returns `device_code` (stored SHA-256-hashed),
  `user_code` (unambiguous alphabet, `XXXX-XXXX`), `verification_uri`
  (`/device`), `expires_in` 600, `interval` 5.
- Human surface: `GET /device` collects **no credentials** — unauthenticated
  visits get a guidance page (portal sign-in first, then reopen the link);
  authenticated users review client + scopes and Approve/Deny; single-shot
  decisions, session-authenticated.
- Token grant consumes the approval exactly once and binds the issued tokens
  to the approving session (`sid`) so offboarding and session revocation cover
  them; banned users answer `invalid_grant` at the token moment.
- RFC 8628 §3.5 polling discipline (`authorization_pending`, `slow_down`) is
  enforced from `last_poll_at`; the daily cleanup removes expired/decided rows.
- Audited at authorize, failed verification, approve/deny, token issuance.

Verified in `tests/oauth/device-flow.test.ts` and
`tests/oauth/extended-grants.test.ts`, plus a live HTTP end-to-end smoke
(2026-11-10, local worker): full flow, introspection, single-use re-poll
lifecycle. The approval surface collects no credentials (see the design doc).
No external-interop testing (RFC-compliant CLI SDKs) has been performed.

## OpenID CIBA, poll mode (2026-11)

`ENABLE_CIBA=true`; otherwise every `/ciba` route 404s and the grant is absent
from discovery. Full flow and limits in `docs/design/ciba.md`.
- `POST /api/auth/oauth2/bc-authorize`: confidential clients only
  (client_secret_basic/post over the hashed-secret storage), `login_hint`
  resolves to exactly one email **or** username (ambiguity, unknown and banned
  identities all answer `unknown_user_id`), `binding_message` sanitized to
  128 chars, caps: 5 pending per user / 20 per client.
- Approval: `GET /ciba` lists pending requests (client, binding message,
  scopes) with a no-JS Approve/Deny form; notification email is best-effort.
- `auth_req_id` is stored SHA-256-hashed and never leaves the backchannel (the
  approval page sees only the digest). Token grant: single-use consumption,
  tokens bound to the approving session, ban re-checked at the token moment,
  RFC polling discipline (`authorization_pending`, `slow_down`).
- Poll mode only; `private_key_jwt` at the backchannel endpoint is not
  implemented (confidential-secret authentication only).

Verified in `tests/oauth/ciba.test.ts` and `tests/oauth/extended-grants.test.ts`,
plus a live HTTP end-to-end smoke (2026-11-10, local worker): full poll
lifecycle, page-form approval, confidential token exchange, channel-mismatch
rejection. Notification email delivery was not exercised (best-effort by
design). No external-interop testing has been performed.

## Accounts, custom attributes and claim release (2026-11)

- `ENABLE_ACCOUNT_CLAIMS`, `ENABLE_ATTRIBUTE_CLAIMS`: token claim release
  flags; both fail closed (tokens are byte-identical when unset). Enable
  together with per-application `claim-release-policies` rows to narrow kinds
  per subject; the optional `attributeAllowlist` releases only listed keys.
- `ENABLE_SCIM_ATTRIBUTE_RELEASE`: outbound SCIM extension push. A deliberate
  per-target decision (privacy review per receiving system); fail-closed.
  Attribute edits self-propagate through queued update operations drained by
  the daily Worker Cron — a cron schedule faster than `17 4 * * *` narrows
  propagation latency when targets need timelier changes. Interop against a
  real local HTTP target is verified end to end by `scripts/scim-smoke.ts`
  (extension on create/update, none on deactivation); the remaining
  production step is running it against the chosen actual target.
- `ENABLE_DEV_MOCKS`: MUST be `false` in production. It exposes
  `/dev/mocks/invitation-email`, whose recorded bodies contain invitation
  tokens. It exists only for headless local testing.
- Invitation email delivery: the selected mail provider (`MAIL_PROVIDER` —
  smtp/resend/cloudflare/maileroo/ses per `docs/design/email-providers.md`)+
  `INVITATION_EMAIL_FROM`/`MAIL_FROM` (or `INVITATION_EMAIL_WEBHOOK_URL` /
  the mock mailbox locally);
  `account.invitation.email` audit events record every delivery attempt.

## Console-managed features: what to check at first deploy (2026-11)

These were added after the sections above; each has a design note under `docs/design/` or `docs/security/`.

**Before the first deploy**
- `AEAD_SEALING_KEY` (32 bytes, base64) must be a Wrangler secret. The console stores e-mail/SMS provider keys (`delivery_settings`) and per-application SCIM tokens (`provisioning`) sealed with it and refuses to save a secret without it. Changing the key later makes those rows unreadable; they are then ignored and the deployment variables apply.
- `wrangler.jsonc` carries `compatibility_flags: ["nodejs_als"]` (a narrow flag, not full Node compatibility). Audit events take the caller's IP and edge geolocation from a per-request context built on it. Confirm the deploy accepts the flag.
- The Worker must sit behind Cloudflare: the recorded client IP is `cf-connecting-ip`, trustworthy only there. The same holds for the sign-in places policy, which uses the edge's `request.cf` position.
- Run `POST /_internal/migrate` after every deploy that adds tables or columns (additive, idempotent): provider settings, places and proofs, entitlements, per-app provisioning, notification preferences, phone verification, SCIM resolution columns.

**After the first deploy** (extends 2a)
1. Audit log: create a group from the console, then open the audit log; the new event must show an IP and a place (city, country). Older events have none.
2. Sign-in places: leave the policy in `observe` first and read `authentication.location.observe` events before enforcing. Put the administrators' group in the exempt groups before enforcing. Browser location needs HTTPS (a secure context), which production has and plain local HTTP may not.
3. E-mail and SMS: in "메시지 발송", save a provider and use "테스트 보내기" for each. Phone number verification and second-factor codes by text work only once SMS is configured.
4. Back-channel logout: an OIDC app's logout address must first be approved in "연동 → 로그아웃 주소 승인". Delivery is best effort. The hostname check does not stop DNS rebinding; keep outbound egress controls in place.
5. SCIM: review [provisioning endpoint security](scim-provisioning-security.md) and establish operator-owned egress controls before sending authenticated traffic. After saving an app's target, use "연결 테스트" before "지금 동기화"; test success does not rule out DNS rebinding. An operation left unfinished for 10 minutes becomes "결과 불명" and stays blocking until an administrator checks the other system and presses "확인했음".
6. Notifications: security notices cannot be switched off by the person; check one (for example change a password) reaches the notification page.

**Known limits**
- Ending one session does not revoke OAuth tokens already issued; ending all sessions, banning, or disconnecting an app does (and notifies apps that registered a back-channel address). SAML single logout is not implemented.
- A text message is never a sign-in: the better-auth phone-number routes answer 404 by design.
