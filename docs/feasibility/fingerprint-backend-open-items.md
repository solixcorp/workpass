# Fingerprint Backend: Implemented Scope and Open Work

**Status:** backend implementation exists; external integration and production enforcement are not verified.

## Implemented in this repository

- Server-side Fingerprint Server API v4 event lookup, regional host selection, event-shape checks, freshness checks, origin checks, and request lookup budgeting.
- Password/username and passkey login risk assessment, applied whenever `FINGERPRINT_SERVER_API_KEY` is set (`FINGERPRINT_BREAK_GLASS=true` is the off switch).
- Interactive OAuth authorization risk checks for an already-authenticated browser session. The event ID must survive the sign-in/authorization continuation; that redirect behavior has not been verified end to end.
- D1 event replay claims, keyed visitor/network digests, coarse device observations, risk decisions, and 30-day trusted-device registration with user/admin revocation APIs.
- Credential-change and suspension paths revoke trust records for password reset/change, admin password change, removal and ban. Other credential/session-revocation mechanisms still need review. A daily Cron cleanup applies initial replay, observation, decision, device, and lookup-budget retention windows even in `disabled` mode. It cleans existing tables even during partial schema initialization and surfaces database failures as failed scheduled invocations.
- Sealed Client Results are explicitly rejected; this implementation only supports event IDs.

## Still requires owner decisions or external access

- Fingerprint account/API key, production region, browser SDK integration, and event-ID delivery on every supported interactive flow.
- Independent MFA/step-up and account recovery. Until these exist and are tested, `enforce` can lock out users on new devices; keep the production mode disabled or observe-only.
- Privacy/legal approval for data categories, notices, jurisdiction, keyed identifiers, retention (24-hour claims, 30-day observations, 90-day decisions/inactive devices), and vendor processing.
- Production false-positive and provider-cost calibration; the initial confidence threshold is only a configurable default, not a validated policy.
- Real D1 concurrent-claim verification, deployed migration/Cron verification, and end-to-end password/passkey/OAuth login and session-withholding verification.
- Identity-library assessment remains separate and open: Better Auth/OIDC are a candidate, SAML IdP/WS-Federation are not implemented, and no actual target-service interoperability has been demonstrated.

## Verification performed

The repository has passed `bun run typecheck`, `bun install --frozen-lockfile`, and `bun run build:check` (Wrangler dry-run). Local Workers smoke checks exercised Cron dispatch and observation cleanup with complete and partial schemas. In local `observe` mode, username/password sign-in without an event returned HTTP 200 and recorded `missing_event`. This does not verify the session-lookup failure branch or a valid provider event. These checks do not exercise a real Fingerprint account, deployed D1, browser event delivery, deployed Cron execution, MFA/recovery, or third-party login compatibility.

## Safe next sequence

1. Do not set `FINGERPRINT_SERVER_API_KEY` until credentials, privacy approval, browser delivery, and a tested recovery path are ready.
2. Apply the application D1 migration before enabling either non-disabled mode. The Cron is not a schema migration; it cleans existing tables and is safe and preferred to leave configured while mode is `disabled` so old data is still deleted.
3. Connect the browser `event_id` and verify redirect continuation, login methods, replay rejection, and recovery.
4. Run observe-only measurements and tune policy with owners. Separately evaluate D1 event-claim concurrency and session withholding on deployed Worker/D1 before proposing enforcement.
5. Review observations, costs, false positives, privacy findings, and recovery readiness before any separately approved gradual enforcement rollout.
