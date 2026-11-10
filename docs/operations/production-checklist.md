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
- **Review gates that remain owner decisions:** MFA policy, recovery channel, production SAML/SCIM target applications (pending owner selection; registration APIs are implemented and ready).

## 2. Deployment window

1. `wrangler deploy` with the temporary override flags (`ENABLE_MIGRATIONS=true`, `ENABLE_ADMIN_BOOTSTRAP=true`).
2. Create the D1 schema: `POST /_internal/migrate` with the migration bearer token — one call; the response records an `admin.migration.executed` audit event.
3. Create the first administrator: `POST /api/admin/bootstrap` — one call (409 afterwards by design); requires the configured `Origin`.
4. Verify the protocols headlessly against production: copy `scripts/run-all-smokes.ts` invocation with production `--base`, fresh migration/bootstrap disabled (they are one-time), and the operator credential — expect the five smokes to pass with the same assertions as local.
5. **Close the window:** redeploy with the override flags back to `false`. Confirm `/_internal/migrate` and `/api/admin/bootstrap` return 404.

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

- `compatibility_date: 2026-11-10` — Node.js compatibility (v1+v2) and
  AsyncLocalStorage are default-on at this date; the explicit `nodejs_als`
  flag was removed as redundant.
- `workers_dev: false` — internal IdP is served by a configured route only.
- `upload_source_maps: true` — stack traces in Workers Logs resolve to source.
- `observability: { enabled: true, head_sampling_rate: 1 }` — Workers Logs
  persists every request (7-day retention).
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
- Legacy password sign-in remains available; migrate accounts by enrolling
  OPAQUE per user (the smoke scripts/opaque-smoke.ts demonstrates the flow).

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
- Revocation/offboarding: `POST /api/oauth1/token/revoke`, explicit
  `revokeOAuth1UserTokens` helper for lifecycle code, disabled consumers.
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
- Invitation email delivery: `RESEND_API_KEY` + `INVITATION_EMAIL_FROM` (or
  `INVITATION_EMAIL_WEBHOOK_URL` / the mock mailbox locally);
  `account.invitation.email` audit events record every delivery attempt.
