# Bootstrap & deployment flags runbook

**Status:** the single page an operator needs when standing up (or re-configuring) the platform.
First-deployment sequencing (DNS, secrets, the one-time migration/bootstrap window, budget review)
lives in `production-checklist.md`; this page covers every configuration flag — what it does, its
default (fail-closed), and how to turn a feature on safely. Defaults matter: **every optional
feature is OFF unless this page says otherwise.**

## 1. Always-required configuration

| Setting | Where | Notes |
|---|---|---|
| `DB` | wrangler binding | D1 database binding. |
| `AUTH_SECRET` | secret | ≥ 32 bytes, unique per environment. |
| `AUTH_BASE_URL` | var | The production HTTPS origin, no path/query/fragment. `http://localhost`/`127.0.0.1` allowed only for local dev. |

Failure mode is startup refusal: without these the worker throws on every auth route rather than
degrading.

## 2. One-time bootstrap window (first deployment only)

1. Deploy with temporary overrides `ENABLE_MIGRATIONS=true`, `ENABLE_ADMIN_BOOTSTRAP=true` plus
   `MIGRATION_TOKEN`, `ADMIN_BOOTSTRAP_TOKEN` (each ≥ 32 bytes).
2. `POST /_internal/migrate` (bearer token) — creates/updates the D1 schema, installs the OIDC
   offboarding guards, application tables, and the audit log. Also run it after every upgrade.
3. `POST /api/admin/bootstrap` — creates the first administrator (username + password). Returns
   409 forever afterwards by design.
4. Redeploy with both flags back to `false`; `/_internal/migrate` and `/api/admin/bootstrap`
   then return 404.

## 3. Feature flag matrix (all default OFF)

| Flag | What it enables | Extra settings required when ON |
|---|---|---|
| `ENABLE_MIGRATIONS` | one-time/schema-upgrade migrate endpoint | `MIGRATION_TOKEN` (≥ 32 bytes) |
| `ENABLE_ADMIN_BOOTSTRAP` | first-administrator bootstrap endpoint | `ADMIN_BOOTSTRAP_TOKEN` (≥ 32 bytes) |
| `ENABLE_DYNAMIC_CLIENT_REGISTRATION` | RFC 7591 DCR at `/api/auth/oauth2/register` | `CLIENT_REGISTRATION_TOKEN` (≥ 32 bytes); optional `OAUTH_RESOURCES` seeds which resource URIs DCR may link |
| `ENABLE_TOKEN_EXCHANGE` | RFC 8693 token exchange grant at `/api/auth/oauth2/token` | `TOKEN_EXCHANGE_ALLOWED_RESOURCES`, resource seed via `OAUTH_RESOURCES` |
| `ENABLE_OAUTH1` | OAuth 1.0a (RFC 5849 HMAC-SHA1) server at `/api/oauth1/*` | `OAUTH1_MANAGEMENT_TOKEN` (≥ 32 bytes), `AEAD_SEALING_KEY` |
| `ENABLE_SSF_RECEIVER` | inbound SET receiver `/api/ssf/receiver/:streamId` | `SSF_STREAMS`, `SSF_MANAGEMENT_TOKEN` (≥ 32 bytes) |
| `ENABLE_SSF_SENDER` | outbound SET dispatch `/api/ssf/*` management + events | `SSF_MANAGEMENT_TOKEN` (≥ 32 bytes), `AEAD_SEALING_KEY` |

An ON flag with a missing/short token **aborts worker startup** (validated in
`src/auth/config.ts`) instead of half-enabling the feature.

Any feature left OFF: its routes return 404, its grant types are absent from OIDC discovery, and
post-deployment smokes for it SKIP. Nothing else degrades.

## 4. Turning the protocol features on (step by step)

### 4.1 Token Exchange (RFC 8693)

1. Seed resources with `OAUTH_RESOURCES` (JSON array). Each entry is a string identifier or
   `{ "identifier": …, "accessTokenTtl": 600, "allowedScopes": […] }`. Identifiers must be https
   URLs. Malformed JSON aborts startup.
2. Give the flow a **delegation target with a shorter TTL**: the exchanged token's lifetime equals
   the target resource's configured TTL, and the platform rejects the exchange unless that TTL is
   safely shorter than the subject token's remaining life. Example:
   `[{"identifier":"https://api.example.com/","accessTokenTtl":600},{"identifier":"https://api.example.com/delegated","accessTokenTtl":300}]`
3. Set `ENABLE_TOKEN_EXCHANGE=true` and `TOKEN_EXCHANGE_ALLOWED_RESOURCES` = JSON map
   `{"<client_id>": ["https://api.example.com/delegated", …]}`. Missing client or resource = deny.
4. Register the confidential client (`token_endpoint_auth_method: "client_secret_basic"`,
   `grant_types` including the exchange URN) via DCR or direct insert; link it to its resources.
5. Verify: `bun run scripts/token-exchange-smoke.ts --base <url> --dcr-token <t>`

Profile guarantees (enforced server-side): same-client confidential auth only, scope narrowing
only, no `openid`/`offline_access` output, `actor_token` and sender-constrained (`cnf`) subjects
rejected, session-bound subjects only, banned accounts rejected, audit-then-issue (audit failure
= no token), delegations never outlive the subject.

### 4.2 OAuth 1.0a server

1. Set `ENABLE_OAUTH1=true`, `OAUTH1_MANAGEMENT_TOKEN` (≥ 32 bytes), and ensure
   `AEAD_SEALING_KEY` is configured (consumer/token secrets are sealed).
2. Register a consumer: `POST /api/oauth1/consumers` (bearer `OAUTH1_MANAGEMENT_TOKEN`) with
   `{"consumer_name": "…"}`. The key/secret are shown once; disable via
   `PATCH /api/oauth1/consumers/{key}` (`{"disabled": true}`).
3. The client runs the standard 3-legged flow: `POST /api/oauth1/initiate` (HMAC-SHA1 signature,
   `oauth_callback` https or `oob`) → user opens
   `GET /api/oauth1/authorize?oauth_token=…` → signs in → approves → verifier delivered by
   callback redirect (or shown for `oob`) → `POST /api/oauth1/token` (single-use verifier).
4. Verify: `tests/oauth1/oauth1-flow.test.ts` covers the full flow; an operator smoke for OAuth 1.0 is
   not in the runner yet (feature test is the current gate).

Notes: temporary credentials expire in 10 minutes; nonces are consumed atomically (replay
protection); `POST /api/oauth1/token/revoke` revokes an access token;
`revokeOAuth1UserTokens` exists for offboarding code paths.

### 4.3 SSF receiver (inbound security event tokens)

1. Set `ENABLE_SSF_RECEIVER=true` and `SSF_MANAGEMENT_TOKEN` (≥ 32 bytes).
2. Describe every trusted sender stream in `SSF_STREAMS` (JSON array):
   `{"id":"legacy-idp","issuer":"https://legacy-idp.example","audience":"internal-auth","jwks":{"keys":[…pinned RSA JWKs…]},"event_types":["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],"delivery_token":"shared-secret","max_age_seconds":3600}`.
   Keys are pinned in configuration — never fetched from a URL at request time.
3. The sender pushes `application/secevent+jwt` to `POST /api/ssf/receiver/<stream id>` with
   `Authorization: Bearer <delivery_token>` when the stream defines one.4. Behaviour: signature/issuer/audience/event-type/jti/iat verified, event queued atomically
   (`ssf_inbox`), and 202 returned for both new and duplicate deliveries. **The inbox is
   deliberately inert** — receiving never mutates accounts until a reviewed per-event handler
   consumes it (see §8).

### 4.4 SSF sender (outbound security event tokens)

1. Set `ENABLE_SSF_SENDER=true` and `SSF_MANAGEMENT_TOKEN`.
2. Register a recipient: `POST /api/ssf/streams`
   `{"id":"downstream-saas","audience":"downstream-saas","endpoint":"https://their.example/ssf","event_types":[…],"delivery_token":"optional-shared-secret"}`
   (https-only endpoints). Public signing JWKS is published at `/api/ssf/jwks.json` (kid `ssf-1`).
3. Dispatch explicitly: `POST /api/ssf/events`
   `{"recipient_id":"downstream-saas","event_type":"…","subject":{"format":"email","email":"…"},"description":{…}}`.
4. Delivery is recorded per attempt with bounded retry (10 attempts, exponential backoff, then
   `abandoned` — never silently dropped); the scheduled worker retries `retry` rows.
   Wiring real account-lifecycle events into `dispatchSSFEvent` is a follow-up; today dispatch is
   explicit/operator-driven.

## 5. Storage cipher / FIPS alignment

- Default writes use `SEALED_STORAGE_CIPHER=xchacha20poly1305` (envelope v1).
- For approved-algorithm (FIPS-aligned) deployments set `SEALED_STORAGE_CIPHER=aes256gcm` —
  writes become NIST SP 800-38D AES-256-GCM envelopes (v2). **Reads are version-driven**, so
  switching the cipher never strands existing rows; rows re-seal lazily on use.
- Always required for features that store secrets (OAuth 1.0, SSF sender, MFA hardware OTP):
  `AEAD_SEALING_KEY` = 32 bytes, base64. Missing key = features throw instead of storing
  plaintext.
- Documented SHA-1 exceptions (standard/vendor-mandated): HOTP (RFC 4226) and Duo Auth API
  signing. True FIPS validation of the Workers runtime is a Cloudflare inquiry, not a code
  change.

## 6. Other flags (unchanged from earlier phases)

| Flag/settings | Default | Notes |
|---|---|---|
| `FINGERPRINT_MODE` | `disabled` | `observe`/`enforce` need `FINGERPRINT_SERVER_API_KEY` (region `us`/`eu`/`ap`); enforce holds logins/sessions on risk findings. **Rotate the key if it was ever exposed in a terminal.** |
| `FINGERPRINT_*` thresholds | provider defaults | `FINGERPRINT_MIN_CONFIDENCE`, `FINGERPRINT_SUSPECT_SCORE_THRESHOLD`, `FINGERPRINT_MAX_EVENT_AGE_SECONDS`, `FINGERPRINT_ALLOWED_ORIGINS`. |
| `ENABLE_DYNAMIC_CLIENT_REGISTRATION` | `false` | see flag matrix. |
| `ENABLE_SCIM_PROVISIONING` / `ENABLE_INBOUND_SCIM` | `false` | SCIM sender/receiver with bearer tokens; `SCIM_DEV_LOOPBACK_TARGET` is dev-only. |
| `SAML_IDP_*` | unset | signing identity/cert/key (and previous pair during rotation) via `bun run scripts/generate-saml-key.ts`. |
| `INVITATION_EMAIL_WEBHOOK_URL`, `MFA_OTP_EMAIL_WEBHOOK_URL`, `MFA_SMS_WEBHOOK_URL`, `MAIL_PROVIDER`, `MAIL_FROM*`, per-provider mail credentials (`docs/design/email-providers.md`), `DUO_*` | unset | OTP delivery, mail provider selection (smtp/resend/cloudflare/maileroo/ses), and Duo Push providers. |
| `OPAQUE_MASTER_KEY` | unset | enables OPAQUE (RFC 9807) zero-password login; its sessions pass the login gate (banned accounts and device risk) before issuance. Rotation = re-enrollment of every credential. |

## 7. Post-deployment verification

- `bun run smoke --base <url> --migrate-token <t> --admin-token <t>` runs the protocol smokes;
  feature-flagged smokes (token exchange) SKIP with a clear line when their flags are off.
- `bun run build:check` before deploying (`wrangler deploy --dry-run`).
- `bun run typecheck` and `bun test tests/` locally — CI parity.
- Watch for `Unhandled Worker request error` log lines after each deploy.

## 8. Known follow-ups (not blockers to deploy)

- SSF inbound events are queued but inert; per-event handlers (session revoked, credential
  changed, …) are a reviewed follow-up.
- SSF/OAuth 1.0/token-exchange external-interop testing with real counterparties not yet done.
- Fingerprint `enforce` mode still needs a live test with the real provider (unit-tested only).
