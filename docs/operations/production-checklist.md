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
- **DNS.** The email-domain route for Tailscale WebFinger (`/.well-known/webfinger` on the company domain) is only needed when that integration goes live (deferred by recorded decision).
- **Review gates that remain owner decisions:** MFA policy, recovery channel, audit backup design, test SaaS targets.

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
